<#
.SYNOPSIS
    Bulk-creates Active Directory user accounts from a CSV file.

.DESCRIPTION
    Reads new-hire records from a CSV, builds a consistent username and UPN,
    creates the account in the correct OU, sets a random temporary password
    that must be changed at first logon, and adds the user to their
    department's security groups.

    Every run writes a results CSV so the help desk has an audit trail of
    what was created, skipped, or failed. Supports -WhatIf for a dry run.

.PARAMETER CsvPath
    Path to the new-hire CSV. Required columns:
    FirstName, LastName, Department, Title, Manager (sAMAccountName), OU

.PARAMETER UpnSuffix
    Domain suffix for the UPN, e.g. contoso.com

.PARAMETER GroupMapPath
    Optional JSON file mapping department names to group lists.

.PARAMETER ResultsPath
    Where to write the results CSV. Defaults to .\onboarding-results-<date>.csv

.EXAMPLE
    .\New-ADUserOnboarding.ps1 -CsvPath .\examples\new-hires.csv -UpnSuffix contoso.com -WhatIf

.EXAMPLE
    .\New-ADUserOnboarding.ps1 -CsvPath .\new-hires.csv -UpnSuffix contoso.com `
        -GroupMapPath .\examples\department-groups.json

.NOTES
    Requires the ActiveDirectory module (RSAT) and rights to create users in the target OUs.
    Temporary passwords are shown ONLY on the technician's console so they can be
    handed to the new hire through a secure channel; they are never written to the
    results file. Users must change them at first logon.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(Mandatory)]
    [ValidatePattern('^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')]
    [string]$UpnSuffix,

    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$GroupMapPath,

    [string]$ResultsPath = ".\onboarding-results-$(Get-Date -Format 'yyyyMMdd-HHmm').csv"
)

#Requires -Modules ActiveDirectory

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-TempPassword {
    # 16 chars, guaranteed upper, lower, digit and symbol, using a CSPRNG.
    param([int]$Length = 16)
    $sets = @(
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!@#$%*?-_'
    )
    $all = -join $sets
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $pick = {
        param($chars)
        $b = [byte[]]::new(4)
        $rng.GetBytes($b)
        $chars[[BitConverter]::ToUInt32($b, 0) % $chars.Length]
    }
    $chars = foreach ($s in $sets) { & $pick $s }
    $chars += 1..($Length - $sets.Count) | ForEach-Object { & $pick $all }
    # Shuffle so the guaranteed characters aren't always first
    -join ($chars | Sort-Object { $b = [byte[]]::new(4); $rng.GetBytes($b); [BitConverter]::ToUInt32($b, 0) })
}

function Get-UniqueSamAccountName {
    # first initial + last name, lowercase, letters only, max 20 chars; append a number if taken
    param([string]$FirstName, [string]$LastName)
    $base = ($FirstName.Substring(0, 1) + $LastName).ToLower() -replace '[^a-z]', ''
    $base = $base.Substring(0, [Math]::Min(18, $base.Length))
    $candidate = $base
    $i = 1
    while (Get-ADUser -Filter "SamAccountName -eq '$candidate'" -ErrorAction SilentlyContinue) {
        $i++
        $candidate = "$base$i"
    }
    $candidate
}

$required = 'FirstName', 'LastName', 'Department', 'Title', 'Manager', 'OU'
$rows = Import-Csv -Path $CsvPath
$missing = $required | Where-Object { $_ -notin $rows[0].PSObject.Properties.Name }
if ($missing) { throw "CSV is missing required column(s): $($missing -join ', ')" }

$groupMap = @{}
if ($GroupMapPath) {
    (Get-Content $GroupMapPath -Raw | ConvertFrom-Json).PSObject.Properties |
        ForEach-Object { $groupMap[$_.Name] = @($_.Value) }
}

$results = foreach ($row in $rows) {
    $status = 'Created'
    $detail = ''
    $sam = $null
    try {
        $first = $row.FirstName.Trim()
        $last  = $row.LastName.Trim()
        $sam   = Get-UniqueSamAccountName -FirstName $first -LastName $last
        $upn   = "$sam@$UpnSuffix"

        if (-not (Get-ADOrganizationalUnit -Identity $row.OU -ErrorAction SilentlyContinue)) {
            throw "OU not found: $($row.OU)"
        }

        $params = @{
            Name                  = "$first $last"
            GivenName             = $first
            Surname               = $last
            DisplayName           = "$first $last"
            SamAccountName        = $sam
            UserPrincipalName     = $upn
            EmailAddress          = $upn
            Department            = $row.Department
            Title                 = $row.Title
            Path                  = $row.OU
            Enabled               = $true
            ChangePasswordAtLogon = $true
        }
        if ($row.Manager) { $params.Manager = $row.Manager }

        if ($PSCmdlet.ShouldProcess($upn, 'Create AD user')) {
            $plain = New-TempPassword
            $params.AccountPassword = ConvertTo-SecureString $plain -AsPlainText -Force
            New-ADUser @params
            Write-Host "Created $upn  temp password: $plain" -ForegroundColor Green
            $plain = $null

            foreach ($group in $groupMap[$row.Department]) {
                Add-ADGroupMember -Identity $group -Members $sam
            }
            $detail = "Groups: $($groupMap[$row.Department] -join '; ')"
        }
        else {
            $status = 'WhatIf'
        }
    }
    catch {
        $status = 'Failed'
        $detail = $_.Exception.Message
        Write-Warning "$($row.FirstName) $($row.LastName): $detail"
    }

    [pscustomobject]@{
        FirstName      = $row.FirstName
        LastName       = $row.LastName
        SamAccountName = $sam
        Department     = $row.Department
        Status         = $status
        Detail         = $detail
        Timestamp      = Get-Date -Format s
    }
}

$results | Export-Csv -Path $ResultsPath -NoTypeInformation
$results | Group-Object Status | ForEach-Object { Write-Host "$($_.Name): $($_.Count)" }
Write-Host "Results written to $ResultsPath"

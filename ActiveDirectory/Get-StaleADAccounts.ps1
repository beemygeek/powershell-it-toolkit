<#
.SYNOPSIS
    Finds enabled user and computer accounts that haven't logged on recently.

.DESCRIPTION
    Stale accounts are a common audit finding and an easy foothold for attackers.
    This report lists enabled users and computers whose lastLogonTimestamp is older
    than -DaysInactive (or that have never logged on), with their OU and creation date
    so a technician can decide whether to disable them.

    lastLogonTimestamp replicates every ~9-14 days, so use thresholds of 30+ days.
    The script is read-only.

.PARAMETER DaysInactive
    Inactivity threshold in days. Default 90.

.PARAMETER SearchBase
    Optional OU to limit the search.

.PARAMETER OutputPath
    Optional CSV path. If omitted, results go to the pipeline.

.EXAMPLE
    .\Get-StaleADAccounts.ps1 -DaysInactive 90 -OutputPath .\stale-accounts.csv

.EXAMPLE
    .\Get-StaleADAccounts.ps1 -DaysInactive 60 | Where-Object Type -eq 'Computer' | Format-Table
#>
[CmdletBinding()]
param(
    [ValidateRange(14, 3650)]
    [int]$DaysInactive = 90,

    [string]$SearchBase,

    [string]$OutputPath
)

#Requires -Modules ActiveDirectory

$cutoff = (Get-Date).AddDays(-$DaysInactive)
$common = @{
    Filter     = 'Enabled -eq $true'
    Properties = 'lastLogonTimestamp', 'whenCreated', 'Description'
}
if ($SearchBase) { $common.SearchBase = $SearchBase }

function ConvertTo-StaleRecord {
    param($Object, [string]$Type)
    $last = if ($Object.lastLogonTimestamp) { [DateTime]::FromFileTime($Object.lastLogonTimestamp) } else { $null }
    if ($null -eq $last -or $last -lt $cutoff) {
        [pscustomobject]@{
            Type          = $Type
            Name          = $Object.SamAccountName
            LastLogon     = $last
            DaysInactive  = if ($last) { [int]((Get-Date) - $last).TotalDays } else { 'Never' }
            Created       = $Object.whenCreated
            OU            = ($Object.DistinguishedName -split ',', 2)[1]
            Description   = $Object.Description
        }
    }
}

$report = @(
    Get-ADUser @common     | ForEach-Object { ConvertTo-StaleRecord $_ 'User' }
    Get-ADComputer @common | ForEach-Object { ConvertTo-StaleRecord $_ 'Computer' }
) | Sort-Object Type, LastLogon

Write-Host "$($report.Count) enabled account(s) inactive for $DaysInactive+ days." -ForegroundColor Yellow

if ($OutputPath) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "Saved to $OutputPath"
}
else {
    $report
}

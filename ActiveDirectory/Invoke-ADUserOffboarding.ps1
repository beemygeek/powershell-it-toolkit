<#
.SYNOPSIS
    Securely offboards a departing employee's Active Directory account.

.DESCRIPTION
    Follows a standard offboarding checklist so nothing is missed:
      1. Records the user's current group memberships (for audit / rehire)
      2. Disables the account and scrambles the password
      3. Removes all group memberships except Domain Users
      4. Stamps the description with date, ticket number and technician
      5. Hides the user from the address list (if the attribute exists)
      6. Moves the account to a "Disabled Users" OU

    Writes a JSON audit record per user. Supports -WhatIf.

.PARAMETER Identity
    sAMAccountName(s) of the user(s) to offboard. Accepts pipeline input.

.PARAMETER TicketNumber
    Help desk ticket that authorized the offboarding.

.PARAMETER DisabledOU
    Distinguished name of the OU disabled accounts are moved into.

.PARAMETER AuditFolder
    Folder for the JSON audit records. Defaults to .\offboarding-audit

.EXAMPLE
    .\Invoke-ADUserOffboarding.ps1 -Identity jdoe -TicketNumber INC-10442 `
        -DisabledOU "OU=Disabled Users,DC=contoso,DC=com" -WhatIf

.EXAMPLE
    'jdoe','asmith' | .\Invoke-ADUserOffboarding.ps1 -TicketNumber INC-10450 `
        -DisabledOU "OU=Disabled Users,DC=contoso,DC=com"
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [string[]]$Identity,

    [Parameter(Mandatory)]
    [string]$TicketNumber,

    [Parameter(Mandatory)]
    [string]$DisabledOU,

    [string]$AuditFolder = '.\offboarding-audit'
)

#Requires -Modules ActiveDirectory

begin {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path $AuditFolder)) { New-Item -ItemType Directory -Path $AuditFolder | Out-Null }
    $tech = "$env:USERDOMAIN\$env:USERNAME"
    $today = Get-Date -Format 'yyyy-MM-dd'
}

process {
    foreach ($id in $Identity) {
        try {
            $user = Get-ADUser -Identity $id -Properties MemberOf, Description, DistinguishedName, msExchHideFromAddressLists -ErrorAction Stop
        }
        catch {
            # msExch attribute may not exist in non-Exchange schemas; retry without it
            try { $user = Get-ADUser -Identity $id -Properties MemberOf, Description, DistinguishedName }
            catch { Write-Warning "User '$id' not found. Skipping."; continue }
        }

        $groups = @($user.MemberOf | ForEach-Object { (Get-ADGroup $_).Name })
        $audit = [ordered]@{
            SamAccountName   = $user.SamAccountName
            OriginalDN       = $user.DistinguishedName
            OriginalGroups   = $groups
            Ticket           = $TicketNumber
            Technician       = $tech
            Date             = (Get-Date -Format s)
            Steps            = @()
        }

        if (-not $PSCmdlet.ShouldProcess($user.SamAccountName, "Offboard (ticket $TicketNumber)")) { continue }

        # 1. Disable + scramble password
        Disable-ADAccount -Identity $user
        $scramble = ConvertTo-SecureString ([guid]::NewGuid().ToString() + 'Aa1!') -AsPlainText -Force
        Set-ADAccountPassword -Identity $user -Reset -NewPassword $scramble
        $audit.Steps += 'Disabled account; password reset to random value'

        # 2. Strip groups
        foreach ($dn in $user.MemberOf) {
            Remove-ADGroupMember -Identity $dn -Members $user -Confirm:$false
        }
        $audit.Steps += "Removed from $($groups.Count) group(s)"

        # 3. Description stamp
        Set-ADUser -Identity $user -Description "Disabled $today | $TicketNumber | $tech"
        $audit.Steps += 'Description stamped'

        # 4. Hide from GAL when Exchange attributes exist
        if ($user.PSObject.Properties.Name -contains 'msExchHideFromAddressLists') {
            Set-ADUser -Identity $user -Replace @{ msExchHideFromAddressLists = $true }
            $audit.Steps += 'Hidden from address lists'
        }

        # 5. Move to disabled OU
        Move-ADObject -Identity $user.DistinguishedName -TargetPath $DisabledOU
        $audit.Steps += "Moved to $DisabledOU"

        $file = Join-Path $AuditFolder "$($user.SamAccountName)-$today.json"
        $audit | ConvertTo-Json -Depth 4 | Set-Content -Path $file -Encoding UTF8
        Write-Host "Offboarded $($user.SamAccountName). Audit: $file" -ForegroundColor Green
    }
}

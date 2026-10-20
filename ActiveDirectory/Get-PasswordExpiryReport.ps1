<#
.SYNOPSIS
    Lists users whose passwords expire soon (or already have).

.DESCRIPTION
    "I can't log in" is one of the most common help desk tickets, and many are
    expired passwords. Running this report each morning lets the help desk reach
    out before users get locked out. Uses msDS-UserPasswordExpiryTimeComputed,
    which already accounts for Fine-Grained Password Policies.

    Read-only.

.PARAMETER WithinDays
    Show users whose password expires within this many days. Default 14.

.PARAMETER IncludeExpired
    Also include users whose password has already expired.

.EXAMPLE
    .\Get-PasswordExpiryReport.ps1 -WithinDays 7 | Format-Table

.EXAMPLE
    .\Get-PasswordExpiryReport.ps1 -WithinDays 14 -IncludeExpired | Export-Csv .\pw-expiry.csv -NoTypeInformation
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$WithinDays = 14,

    [switch]$IncludeExpired
)

#Requires -Modules ActiveDirectory

$now = Get-Date
$horizon = $now.AddDays($WithinDays)

Get-ADUser -Filter 'Enabled -eq $true -and PasswordNeverExpires -eq $false' `
    -Properties DisplayName, EmailAddress, 'msDS-UserPasswordExpiryTimeComputed', PasswordLastSet |
    ForEach-Object {
        $raw = $_.'msDS-UserPasswordExpiryTimeComputed'
        # 0 / max value = no expiry (e.g., must change at next logon or not set)
        if (-not $raw -or $raw -eq 0 -or $raw -ge [Int64]::MaxValue) { return }
        $expires = [DateTime]::FromFileTime($raw)

        $isExpired = $expires -lt $now
        if (($isExpired -and $IncludeExpired) -or (-not $isExpired -and $expires -le $horizon)) {
            [pscustomobject]@{
                User            = $_.SamAccountName
                DisplayName     = $_.DisplayName
                Email           = $_.EmailAddress
                PasswordLastSet = $_.PasswordLastSet
                Expires         = $expires
                DaysLeft        = [int][Math]::Floor(($expires - $now).TotalDays)
                Status          = if ($isExpired) { 'Expired' } else { 'Expiring' }
            }
        }
    } |
    Sort-Object Expires

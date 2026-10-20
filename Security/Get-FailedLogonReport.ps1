<#
.SYNOPSIS
    Summarizes failed logons (Event ID 4625) and lockouts (4740) to spot brute force
    and password spraying.

.DESCRIPTION
    Pulls failed-logon events from the Security log of a domain controller or member
    server and groups them two ways:

      - By source IP / workstation: one source failing against MANY accounts
        suggests password spraying.
      - By target account: MANY failures against ONE account suggests brute force
        (or just a user with a stale saved password on their phone).

    Failure reasons are decoded from the SubStatus code so the help desk can tell
    "bad password" from "account disabled" at a glance. Read-only.

.PARAMETER ComputerName
    Machine to query. Defaults to local. Query a DC for domain-wide lockouts.

.PARAMETER Hours
    Look-back window. Default 24.

.PARAMETER SprayThreshold
    Distinct accounts from one source that triggers a spraying flag. Default 5.

.EXAMPLE
    .\Get-FailedLogonReport.ps1 -ComputerName DC01 -Hours 4

.NOTES
    Requires read access to the Security log (Event Log Readers or admin).
    MITRE ATT&CK: T1110.001 (Password Guessing), T1110.003 (Password Spraying)
#>
[CmdletBinding()]
param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [ValidateRange(1, 720)]
    [int]$Hours = 24,
    [int]$SprayThreshold = 5
)

$subStatus = @{
    '0xc000006a' = 'Bad password'
    '0xc0000064' = 'User does not exist'
    '0xc0000234' = 'Account locked out'
    '0xc0000072' = 'Account disabled'
    '0xc000006f' = 'Outside allowed hours'
    '0xc0000070' = 'Workstation restriction'
    '0xc0000071' = 'Password expired'
    '0xc0000193' = 'Account expired'
    '0xc0000224' = 'Must change password'
}

$start = (Get-Date).AddHours(-$Hours)
try {
    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
        LogName = 'Security'; Id = 4625, 4740; StartTime = $start } -ErrorAction Stop
}
catch [System.Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Host "No failed logons or lockouts on $ComputerName in the last $Hours hour(s)." -ForegroundColor Green
        return
    }
    throw
}

$failures = foreach ($e in $events | Where-Object Id -eq 4625) {
    $x = [xml]$e.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    $code = "$($d.SubStatus)".ToLower()
    [pscustomobject]@{
        Time        = $e.TimeCreated
        Account     = "$($d.TargetDomainName)\$($d.TargetUserName)"
        SourceIP    = $d.IpAddress
        Workstation = $d.WorkstationName
        LogonType   = $d.LogonType
        Reason      = if ($subStatus.ContainsKey($code)) { $subStatus[$code] } else { $code }
    }
}

$lockouts = $events | Where-Object Id -eq 4740 | ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ Time = $_.TimeCreated; Account = $d.TargetUserName; CallerComputer = $d.TargetDomainName }
}

Write-Host "`n=== $($failures.Count) failed logon(s), $(@($lockouts).Count) lockout(s) on $ComputerName since $start ===`n" -ForegroundColor Cyan

Write-Host '--- By source (password spraying check) ---' -ForegroundColor Yellow
$failures | Group-Object { if ($_.SourceIP -and $_.SourceIP -ne '-') { $_.SourceIP } else { $_.Workstation } } |
    ForEach-Object {
        $accounts = @($_.Group.Account | Sort-Object -Unique)
        [pscustomobject]@{
            Source           = $_.Name
            Failures         = $_.Count
            DistinctAccounts = $accounts.Count
            Flag             = if ($accounts.Count -ge $SprayThreshold) { 'POSSIBLE SPRAY' } else { '' }
        }
    } | Sort-Object DistinctAccounts, Failures -Descending | Format-Table -AutoSize

Write-Host '--- By account (brute force check) ---' -ForegroundColor Yellow
$failures | Group-Object Account | ForEach-Object {
    [pscustomobject]@{
        Account     = $_.Name
        Failures    = $_.Count
        Sources     = (@($_.Group.SourceIP | Sort-Object -Unique) -join ', ')
        TopReason   = ($_.Group | Group-Object Reason | Sort-Object Count -Descending | Select-Object -First 1).Name
    }
} | Sort-Object Failures -Descending | Select-Object -First 20 | Format-Table -AutoSize

if ($lockouts) {
    Write-Host '--- Lockouts (4740) ---' -ForegroundColor Yellow
    $lockouts | Sort-Object Time | Format-Table -AutoSize
}

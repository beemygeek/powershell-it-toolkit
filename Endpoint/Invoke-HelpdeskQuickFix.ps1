<#
.SYNOPSIS
    Runs common first-line fixes on the local Windows machine and logs what was done.

.DESCRIPTION
    Bundles the steps a Tier 1 technician runs again and again, so they're done the
    same way every time and leave a log for the ticket. Pick only the fixes you need:

      -Network   Flush DNS, renew DHCP lease, reset Winsock (reboot needed for Winsock)
      -Policy    Force a Group Policy refresh
      -Teams     Clear the Microsoft Teams (new and classic) cache for the current user
      -Print     Restart the Print Spooler and clear stuck jobs
      -TempFiles Clear the current user's temp folder

    Supports -WhatIf. Run from an elevated prompt for -Network and -Print.

.EXAMPLE
    .\Invoke-HelpdeskQuickFix.ps1 -Network -Policy -WhatIf

.EXAMPLE
    .\Invoke-HelpdeskQuickFix.ps1 -Print -LogPath C:\Temp\ticket-INC10500.log
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Network,
    [switch]$Policy,
    [switch]$Teams,
    [switch]$Print,
    [switch]$TempFiles,
    [string]$LogPath = (Join-Path $env:TEMP "helpdesk-quickfix-$(Get-Date -Format 'yyyyMMdd-HHmmss').log")
)

function Write-Log {
    param([string]$Message)
    $line = "$(Get-Date -Format s)  $Message"
    Write-Host $line
    Add-Content -Path $LogPath -Value $line
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not ($Network -or $Policy -or $Teams -or $Print -or $TempFiles)) {
    Write-Warning 'No fix selected. Use -Network, -Policy, -Teams, -Print and/or -TempFiles.'
    return
}
if (($Network -or $Print) -and -not $isAdmin) {
    throw '-Network and -Print require an elevated (Run as administrator) session.'
}

Write-Log "Quick fix started on $env:COMPUTERNAME by $env:USERNAME"

if ($Network -and $PSCmdlet.ShouldProcess('Network stack', 'Flush DNS, renew DHCP, reset Winsock')) {
    Clear-DnsClientCache;                    Write-Log 'DNS cache flushed'
    ipconfig /release | Out-Null
    ipconfig /renew   | Out-Null;            Write-Log 'DHCP lease renewed'
    netsh winsock reset | Out-Null;          Write-Log 'Winsock reset (reboot required)'
}

if ($Policy -and $PSCmdlet.ShouldProcess('Group Policy', 'gpupdate /force')) {
    gpupdate /force /wait:120 | Out-Null;    Write-Log 'Group Policy refreshed'
}

if ($Teams -and $PSCmdlet.ShouldProcess('Teams cache', 'Stop Teams and clear cache')) {
    Get-Process -Name 'ms-teams', 'Teams' -ErrorAction SilentlyContinue | Stop-Process -Force
    $paths = @(
        "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams",  # new Teams
        "$env:APPDATA\Microsoft\Teams"                                                     # classic Teams
    )
    foreach ($p in $paths | Where-Object { Test-Path $_ }) {
        Get-ChildItem $p -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Cleared Teams cache at $p"
    }
}

if ($Print -and $PSCmdlet.ShouldProcess('Print Spooler', 'Restart and clear queue')) {
    Stop-Service -Name Spooler -Force
    Get-ChildItem "$env:SystemRoot\System32\spool\PRINTERS" -File -ErrorAction SilentlyContinue | Remove-Item -Force
    Start-Service -Name Spooler;             Write-Log 'Print Spooler restarted, stuck jobs cleared'
}

if ($TempFiles -and $PSCmdlet.ShouldProcess($env:TEMP, 'Clear temp files')) {
    $before = (Get-ChildItem $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Get-ChildItem $env:TEMP -Force -ErrorAction SilentlyContinue |
        Where-Object FullName -ne $LogPath |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    $after = (Get-ChildItem $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Write-Log ("Temp files cleared: {0:N1} MB freed" -f (($before - $after) / 1MB))
}

Write-Log "Done. Log: $LogPath"

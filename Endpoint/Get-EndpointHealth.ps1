<#
.SYNOPSIS
    One-shot health check for one or many Windows endpoints.

.DESCRIPTION
    Collects the facts a technician usually checks first on a "my computer is slow /
    acting weird" ticket, in one object per machine:

      - OS version/build and uptime
      - Free space on the system drive (flags < 15%)
      - Memory usage
      - Pending reboot (CBS, Windows Update, pending file renames)
      - Microsoft Defender status, signature age, real-time protection
      - Most recent installed hotfix
      - BitLocker status of the system drive

    Uses CIM over WinRM for remote machines. Read-only.

.PARAMETER ComputerName
    One or more computers. Defaults to the local machine.

.EXAMPLE
    .\Get-EndpointHealth.ps1

.EXAMPLE
    Get-Content .\computers.txt | .\Get-EndpointHealth.ps1 | Where-Object Issues | Format-List
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline)]
    [string[]]$ComputerName = $env:COMPUTERNAME
)

process {
    foreach ($computer in $ComputerName) {
        $issues = [System.Collections.Generic.List[string]]::new()
        try {
            $session = if ($computer -in $env:COMPUTERNAME, 'localhost', '.') {
                New-CimSession
            } else {
                New-CimSession -ComputerName $computer -ErrorAction Stop
            }
        }
        catch {
            [pscustomobject]@{ ComputerName = $computer; Reachable = $false; Issues = "Unreachable: $($_.Exception.Message)" }
            continue
        }

        try {
            $os   = Get-CimInstance -CimSession $session Win32_OperatingSystem
            $disk = Get-CimInstance -CimSession $session Win32_LogicalDisk -Filter "DeviceID='$($os.SystemDrive)'"
            $uptime = (Get-Date) - $os.LastBootUpTime
            $freePct = [Math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)
            $memPct  = [Math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 1)

            if ($freePct -lt 15)          { $issues.Add("Low disk: $freePct% free") }
            if ($uptime.TotalDays -gt 14) { $issues.Add("Uptime $([int]$uptime.TotalDays) days") }
            if ($memPct -gt 90)           { $issues.Add("Memory $memPct% used") }

            # Pending reboot checks via the registry provider
            $hklm = [uint32]2147483650
            $reg = @{ CimSession = $session; Namespace = 'root/default'; ClassName = 'StdRegProv' }
            $keyExists = {
                param($path)
                $r = Invoke-CimMethod @reg -MethodName EnumKey -Arguments @{ hDefKey = $hklm; sSubKeyName = $path }
                $r.ReturnValue -eq 0
            }
            $pending = (& $keyExists 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                       (& $keyExists 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
            $renames = Invoke-CimMethod @reg -MethodName GetMultiStringValue -Arguments @{
                hDefKey = $hklm; sSubKeyName = 'SYSTEM\CurrentControlSet\Control\Session Manager'; sValueName = 'PendingFileRenameOperations' }
            if ($renames.sValue) { $pending = $true }
            if ($pending) { $issues.Add('Reboot pending') }

            $defender = Get-CimInstance -CimSession $session -Namespace root/Microsoft/Windows/Defender MSFT_MpComputerStatus -ErrorAction SilentlyContinue
            if ($defender) {
                if (-not $defender.RealTimeProtectionEnabled) { $issues.Add('Defender real-time protection OFF') }
                if ($defender.AntivirusSignatureAge -gt 3)    { $issues.Add("Defender signatures $($defender.AntivirusSignatureAge) days old") }
            } else {
                $issues.Add('Defender status unavailable (third-party AV?)')
            }

            $lastPatch = Get-CimInstance -CimSession $session Win32_QuickFixEngineering |
                Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
            if ($lastPatch -and ((Get-Date) - $lastPatch.InstalledOn).TotalDays -gt 45) {
                $issues.Add("Last patch $($lastPatch.InstalledOn.ToShortDateString())")
            }

            $bitlocker = Get-CimInstance -CimSession $session -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption `
                Win32_EncryptableVolume -Filter "DriveLetter='$($os.SystemDrive)'" -ErrorAction SilentlyContinue
            $blStatus = switch ($bitlocker.ProtectionStatus) { 1 { 'On' } 0 { 'Off' } default { 'Unknown' } }
            if ($blStatus -eq 'Off') { $issues.Add('BitLocker off on system drive') }

            [pscustomobject]@{
                ComputerName      = $computer
                Reachable         = $true
                OS                = "$($os.Caption) ($($os.BuildNumber))"
                UptimeDays        = [Math]::Round($uptime.TotalDays, 1)
                SystemDriveFreePct = $freePct
                MemoryUsedPct     = $memPct
                RebootPending     = $pending
                DefenderRTP       = $defender.RealTimeProtectionEnabled
                SignatureAgeDays  = $defender.AntivirusSignatureAge
                LastHotfix        = $lastPatch.HotFixID
                LastHotfixDate    = $lastPatch.InstalledOn
                BitLocker         = $blStatus
                Issues            = $issues -join '; '
            }
        }
        finally {
            Remove-CimSession $session
        }
    }
}

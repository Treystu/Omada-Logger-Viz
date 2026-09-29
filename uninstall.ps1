<#
Omada Syslog Receiver - uninstaller.

Removes the Task Scheduler task and the firewall rule. Log data in
%LOCALAPPDATA%\OmadaSyslog is NOT touched.
#>
$ErrorActionPreference = 'Continue'
$TaskName = 'Omada Syslog Receiver'
$RuleName = 'Omada Syslog UDP 514 inbound'

# --- self-elevate ------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath) -Verb RunAs
    exit
}

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName 'Omada Syslog Watchdog' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Omada Syslog Watchdog' -Confirm:$false -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName 'Omada Viz Server' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Omada Viz Server' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Omada Viz.lnk') -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

Write-Host "Removed tasks (receiver, watchdog, viz) + desktop shortcut and firewall rule '$RuleName'."
Write-Host 'Log data left untouched at %LOCALAPPDATA%\OmadaSyslog'

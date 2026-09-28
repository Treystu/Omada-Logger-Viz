<#
Omada Syslog Receiver - one-time installer.

What it does (scoped to the current user - no machine-global install):
  1. Adds an inbound Windows Firewall rule: allow UDP 514 from 192.168.0.0/24
     (Private + Domain profiles). Port rules are machine-wide by nature, but
     this only lets syslog reach this machine - nothing more.
  2. Registers a per-user Task Scheduler task running omada_syslog.py as the
     current user
     (S4U logon: runs whether logged on or not, starts at boot and logon),
     via pythonw.exe - no console window, limited privileges, unlimited
     runtime, restart-on-failure.
  3. Starts the task immediately.

Usage (self-elevates; UAC prompt will appear if not already admin):
    .\install.ps1
    .\install.ps1 -TaskArgs '--max-mb 100'     # override receiver args in the task

Log data lives in %LOCALAPPDATA%\OmadaSyslog (kept on uninstall).
#>
param(
    [string]$TaskArgs = ''
)

$ErrorActionPreference = 'Stop'
$TaskName = 'Omada Syslog Receiver'
$RuleName = 'Omada Syslog UDP 514 inbound'
$LogDir   = Join-Path $env:LOCALAPPDATA 'OmadaSyslog'
$Subnet   = '192.168.0.0/24'

# --- self-elevate ------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($TaskArgs) { $argList += @('-TaskArgs', $TaskArgs) }
    Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs
    exit
}

# --- locate pythonw ----------------------------------------------------------
$pyw = $null
$c = Get-Command pythonw.exe -ErrorAction SilentlyContinue
if ($c) { $pyw = $c.Source }
if (-not $pyw) {
    $c = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($c) {
        $cand = Join-Path (Split-Path -Parent $c.Source) 'pythonw.exe'
        if (Test-Path -LiteralPath $cand) { $pyw = $cand } else { $pyw = $c.Source }
    }
}
if (-not $pyw) { throw 'Python not found on PATH (need pythonw.exe or python.exe).' }

$script = Join-Path $PSScriptRoot 'omada_syslog.py'
if (-not (Test-Path -LiteralPath $script)) { throw "omada_syslog.py not found next to installer: $script" }

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# --- firewall rule (idempotent) ----------------------------------------------
if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Allow `
        -Protocol UDP -LocalPort 514 -RemoteAddress $Subnet -Profile Private, Domain | Out-Null
    Write-Host "Added firewall rule '$RuleName' (UDP 514 from $Subnet, Private+Domain)"
}
else {
    Write-Host "Firewall rule already present."
}

# --- scheduled task -----------------------------------------------------------
$argLine = ('"' + $script + '"') + ' --log-file "' + (Join-Path $LogDir 'firewall.log') + '"'
if ($TaskArgs) { $argLine = $argLine + ' ' + $TaskArgs }   # appended last: overrides earlier flags

$action    = New-ScheduledTaskAction -Execute $pyw -Argument $argLine -WorkingDirectory $PSScriptRoot
$bootTrigger  = New-ScheduledTaskTrigger -AtStartup
$logonTrigger = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$trigger      = @($bootTrigger, $logonTrigger)
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force `
    -Description 'UDP/514 syslog receiver for TP-Link Omada ER8411 remote logging (per-user)' | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2

$state = (Get-ScheduledTask -TaskName $TaskName).State
Write-Host "Installed '$TaskName' (state: $state)"
Write-Host "Runs as:   $env:USERDOMAIN\$env:USERNAME (S4U, starts with Windows)"
Write-Host "Receiver:  $pyw $argLine"
Write-Host "Log file:  $LogDir\firewall.log"

# --- watchdog task (auto-restart receiver when the raw log goes stale) --------
$wdScript = Join-Path $PSScriptRoot 'watchdog.ps1'
if (Test-Path -LiteralPath $wdScript) {
    $wdAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $wdScript + '"') `
        -WorkingDirectory $PSScriptRoot
    $wdTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::FromDays(3650))
    $wdPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Highest
    $wdSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName 'Omada Syslog Watchdog' -Action $wdAction -Trigger $wdTrigger `
        -Principal $wdPrincipal -Settings $wdSettings -Force `
        -Description 'Restarts the receiver task if the raw log goes stale (hung process / post-sleep)' | Out-Null
    Write-Host "Watchdog registered (every 5 min, 10 min stale threshold, 30 min restart cooldown)"
}

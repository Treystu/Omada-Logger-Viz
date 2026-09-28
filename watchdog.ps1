<#
Omada Syslog Watchdog - restarts the receiver task if the raw log goes stale
(hung process, e.g. after machine sleep, or otherwise stuck).

Runs every 5 minutes via Task Scheduler (elevated, per-user). Behavior:
  - raw log written within the last 10 min  -> all good, exit
  - otherwise: 90 s grace period (machine may have just woken; give the
    receiver and the network a moment to resume), then re-check
  - still stale -> restart the receiver task (at most once per 30 min
    cooldown, so a genuinely quiet network cannot cause churn)
Restarts are safe: the receiver folds any un-tallied raw lines exactly once
on startup.
#>
param(
    [int]$StaleMinutes = 10,
    [int]$CooldownMinutes = 30
)

$ErrorActionPreference = 'Continue'
$dir      = Join-Path $env:LOCALAPPDATA 'OmadaSyslog'
$log      = Join-Path $dir 'firewall.log'
$marker   = Join-Path $dir '.watchdog-restart'
$taskName = 'Omada Syslog Receiver'

$fi = Get-Item -LiteralPath $log -ErrorAction SilentlyContinue
if (-not $fi) { exit }

$ageMin = ((Get-Date) - $fi.LastWriteTime).TotalMinutes
if ($ageMin -le $StaleMinutes) { exit }

# grace period before acting
Start-Sleep -Seconds 90
$fi = Get-Item -LiteralPath $log -ErrorAction SilentlyContinue
if (-not $fi) { exit }
$ageMin = ((Get-Date) - $fi.LastWriteTime).TotalMinutes
if ($ageMin -le $StaleMinutes) { exit }

# cooldown: at most one forced restart per cooldown window
$mi = Get-Item -LiteralPath $marker -ErrorAction SilentlyContinue
if ($mi) {
    $sinceRestart = ((Get-Date) - $mi.LastWriteTime).TotalMinutes
    if ($sinceRestart -lt $CooldownMinutes) { exit }
}

Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Set-Content -LiteralPath $marker -Value (Get-Date -Format o)

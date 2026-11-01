<#
Omada Syslog Watchdog - keeps the receiver AND the dashboard alive.

Runs every 5 minutes via Task Scheduler (elevated, per-user).

Receiver: raw log written within the last 10 min -> all good. Otherwise a
  90 s grace period (machine may have just woken; give the receiver and the
  network a moment to resume), then a re-check. Still stale -> restart the
  receiver task, at most once per 30 min cooldown (a genuinely quiet network
  cannot cause churn).

Viz: port 8780 must answer HTTP 200. A bound-but-silent listener gets one
  15 s retry, then is replaced by a fresh headless instance, at most once
  per 5 min cooldown. This also brings the dashboard up at boot without
  waiting for an interactive logon.

Actions are appended to %LOCALAPPDATA%\OmadaSyslog\watchdog.log so future
audits have evidence. Restarts are safe: the receiver folds any un-tallied
raw lines exactly once on startup.
#>
param(
    [int]$StaleMinutes = 10,
    [int]$CooldownMinutes = 30,
    [int]$VizCooldownMinutes = 5,
    [int]$VizPort = 8780
)

$ErrorActionPreference = 'Continue'
$root      = $PSScriptRoot
$dir       = Join-Path $env:LOCALAPPDATA 'OmadaSyslog'
$log       = Join-Path $dir 'firewall.log'
$marker    = Join-Path $dir '.watchdog-restart'
$vizMarker = Join-Path $dir '.viz-watchdog-restart'
$actionLog = Join-Path $dir 'watchdog.log'
$taskName  = 'Omada Syslog Receiver'

function Write-Action([string]$msg) {
    $line = "{0} {1}" -f (Get-Date -Format o), $msg
    $fi = Get-Item -LiteralPath $actionLog -ErrorAction SilentlyContinue
    if ($fi -and $fi.Length -gt 1MB) {
        Set-Content -LiteralPath $actionLog -Value $line
    } else {
        Add-Content -LiteralPath $actionLog -Value $line
    }
}

function Test-Viz {
    $conn = @(Get-NetTCPConnection -LocalPort $VizPort -State Listen -ErrorAction SilentlyContinue)
    if ($conn.Count -eq 0) { return @{ Up = $false; Pid = 0 } }
    $vizPid = $conn[0].OwningProcess
    try {
        $r = Invoke-WebRequest -Uri ("http://127.0.0.1:{0}/" -f $VizPort) -UseBasicParsing -TimeoutSec 5
        if ($r.StatusCode -eq 200) { return @{ Up = $true; Pid = $vizPid } }
    } catch { }
    return @{ Up = $false; Pid = $vizPid; Slow = $true }
}

# --- receiver: restart the task if the raw log went stale ---------------------
$fi = Get-Item -LiteralPath $log -ErrorAction SilentlyContinue
$stale = $true
if ($fi) { $stale = (((Get-Date) - $fi.LastWriteTime).TotalMinutes -gt $StaleMinutes) }

if ($stale) {
    Start-Sleep -Seconds 90
    $fi = Get-Item -LiteralPath $log -ErrorAction SilentlyContinue
    if ($fi) { $stale = (((Get-Date) - $fi.LastWriteTime).TotalMinutes -gt $StaleMinutes) }
}

if ($stale) {
    $cool = $true
    $mi = Get-Item -LiteralPath $marker -ErrorAction SilentlyContinue
    if ($mi -and ((Get-Date) - $mi.LastWriteTime).TotalMinutes -lt $CooldownMinutes) { $cool = $false }
    if ($cool) {
        Set-Content -LiteralPath $marker -Value (Get-Date -Format o)
        Write-Action "receiver stale - restarting task '$taskName'"
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
}

# --- viz: replace a dead or silent dashboard server ---------------------------
$v = Test-Viz
if (-not $v.Up -and $v.Slow) {
    Start-Sleep -Seconds 15
    $v = Test-Viz
}

if (-not $v.Up) {
    $cool = $true
    $mi = Get-Item -LiteralPath $vizMarker -ErrorAction SilentlyContinue
    if ($mi -and ((Get-Date) - $mi.LastWriteTime).TotalMinutes -lt $VizCooldownMinutes) { $cool = $false }
    $script = Join-Path $root 'omada_viz.py'
    if ($cool -and (Test-Path -LiteralPath $script)) {
        Set-Content -LiteralPath $vizMarker -Value (Get-Date -Format o)
        if ($v.Pid -gt 0) {
            Write-Action "viz silent (PID $($v.Pid)) - replacing"
            Stop-Process -Id $v.Pid -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        } else {
            Write-Action "viz down - starting headless on port $VizPort"
        }
        $pyw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
        if (-not $pyw) {
            $py = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
            if ($py) {
                $cand = Join-Path (Split-Path -Parent $py) 'pythonw.exe'
                if (Test-Path -LiteralPath $cand) { $pyw = $cand } else { $pyw = $py }
            }
        }
        if ($pyw) {
            Start-Process -FilePath $pyw -ArgumentList ('"' + $script + '"'), '--port', "$VizPort" -WorkingDirectory $root -WindowStyle Hidden
        } else {
            Write-Action "pythonw not found - viz not started"
        }
    }
}

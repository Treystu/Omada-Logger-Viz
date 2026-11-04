<#
Omada Syslog Watchdog - keeps the receiver AND the dashboard alive.

Runs every 5 minutes via Task Scheduler (limited, per-user).

Receiver: a local heartbeat is refreshed every 30 s while the receiver is
  bound and responsive, even when no syslog traffic arrives. A stale heartbeat
  gets a 90 s grace period, then a re-check before restarting the receiver task.
  Missing heartbeats are monitored only after this installer arms the check or
  a heartbeat has been seen; older installations remain observation-only.
  Failed restarts are logged and retried no more than once per 30 min.

Viz: port 8780 must answer HTTP 200. A bound-but-silent listener gets one
  15 s retry, then is replaced by a fresh headless instance, at most once
  per 5 min cooldown. This also brings the dashboard up at boot without
  waiting for an interactive logon.

Actions are appended to %LOCALAPPDATA%\OmadaSyslog\watchdog.log so future
audits have evidence. Restarts are safe: the receiver resumes from its saved
checkpoint when that checkpoint is present in the raw log; otherwise it reports
recovery failure and keeps raw ingestion running without advancing tallies.
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
$heartbeat = Join-Path $dir 'receiver.heartbeat'
$armed     = Join-Path $dir '.receiver-heartbeat-armed'
$marker    = Join-Path $dir '.watchdog-restart'
$vizMarker = Join-Path $dir '.viz-watchdog-restart'
$actionLog = Join-Path $dir 'watchdog.log'
$taskName  = 'Omada Syslog Receiver'
. (Join-Path $PSScriptRoot 'watchdog-health.ps1')

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

# --- receiver: check liveness independently of network traffic -----------------
$health = Get-ReceiverHeartbeatState -HeartbeatPath $heartbeat -ArmedPath $armed `
    -Now (Get-Date) -StaleMinutes $StaleMinutes
if ($health.HeartbeatExists -and -not $health.Armed) {
    Set-Content -LiteralPath $armed -Value (Get-Date -Format o)
    $health = Get-ReceiverHeartbeatState -HeartbeatPath $heartbeat -ArmedPath $armed `
        -Now (Get-Date) -StaleMinutes $StaleMinutes
}
$stale = $health.Stale
$missingHeartbeat = $health.Missing

if ($stale) {
    Start-Sleep -Seconds 90
    $health = Get-ReceiverHeartbeatState -HeartbeatPath $heartbeat -ArmedPath $armed `
        -Now (Get-Date) -StaleMinutes $StaleMinutes
    $stale = $health.Stale
    $missingHeartbeat = $health.Missing
    if ($health.StartingGrace) {
        Write-Action 'receiver heartbeat is within startup grace; monitoring continues'
    }
}

if ($stale) {
    if (Test-ReceiverRestartCooldown -MarkerPath $marker -Now (Get-Date) `
            -CooldownMinutes $CooldownMinutes) {
        Set-Content -LiteralPath $marker -Value (Get-Date -Format o)
        if ($missingHeartbeat) {
            Write-Action "receiver heartbeat missing after install/previous operation; restarting task '$taskName'"
        } else {
            Write-Action "receiver heartbeat stale; restarting task '$taskName'"
        }
        try {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
        } catch {
            Write-Action "ERROR stopping receiver task '$taskName': $($_.Exception.Message)"
        }
        Start-Sleep -Seconds 2
        try {
            Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
            Start-Sleep -Seconds 2
            $taskState = (Get-ScheduledTask -TaskName $taskName -ErrorAction Stop).State
            if ($taskState -eq 'Running') {
                Write-Action "receiver task restart requested; scheduler state=$taskState"
            } else {
                Write-Action "ERROR receiver task did not enter Running after restart; state=$taskState"
            }
        } catch {
            Write-Action "ERROR starting receiver task '$taskName': $($_.Exception.Message)"
        }
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

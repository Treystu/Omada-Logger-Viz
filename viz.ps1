<#
Omada Viz launcher - one click to the live traffic dashboard.

    .\viz.ps1              start the viz server (if needed) + open the browser
    .\viz.ps1 -Stop        stop the running viz server
    .\viz.ps1 -Port 8790   use a different port
    .\viz.ps1 -NoBrowser   start/stop without opening a page (scripting/tests)

The server runs headless (pythonw, hidden window). The desktop shortcut that
install.ps1 creates points here, so double-clicking "Omada Viz" just works.
#>
param(
    [int]$Port = 8780,
    [switch]$Stop,
    [switch]$NoBrowser
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

function Test-Viz([int]$p) {
    try {
        $r = Invoke-WebRequest -Uri ("http://127.0.0.1:{0}/" -f $p) -UseBasicParsing -TimeoutSec 4
        return ($r.StatusCode -eq 200 -and $r.Content -match 'tallies scatter')
    } catch {
        return $false
    }
}

if ($Stop) {
    # stop the boot task first (if -VizBoot was used) so restart-on-failure
    # doesn't resurrect the server right after we kill the process
    Stop-ScheduledTask -TaskName 'Omada Viz Server' -ErrorAction SilentlyContinue
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($conn -and (Test-Viz $Port)) {
        Stop-Process -Id $conn[0].OwningProcess -Force
        Write-Host "viz stopped (port $Port)"
    } elseif ($conn) {
        Write-Host "port $Port is used by another program - not touching it"
    } else {
        Write-Host "viz not running"
    }
    exit 0
}

if (Test-Viz $Port) {
    Write-Host "viz already running on port $Port"
} else {
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        Write-Host "port $Port is used by another program - not starting"
        exit 1
    }
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
    if (-not $pyw) { Write-Host 'Python not found on PATH'; exit 1 }
    Start-Process -FilePath $pyw -ArgumentList ('omada_viz.py', '--port', $Port) `
        -WorkingDirectory $here -WindowStyle Hidden
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if (Test-Viz $Port) { break }
        Start-Sleep -Milliseconds 500
    }
    if (Test-Viz $Port) {
        Write-Host "viz started on port $Port (headless)"
    } else {
        Write-Host "viz failed to start on port $Port"
        exit 1
    }
}

if (-not $NoBrowser) {
    Start-Process ("http://localhost:{0}" -f $Port)
}

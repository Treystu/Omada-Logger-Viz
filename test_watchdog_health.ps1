$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'watchdog-health.ps1')

function Assert-Case([string]$Name, [bool]$Condition) {
    if (-not $Condition) { throw "FAILED: $Name" }
    Write-Output "PASS: $Name"
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("omada-watchdog-test-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $heartbeat = Join-Path $tmp 'receiver.heartbeat'
    $armed = Join-Path $tmp '.receiver-heartbeat-armed'
    $restartMarker = Join-Path $tmp '.watchdog-restart'
    $now = Get-Date

    $state = Get-ReceiverHeartbeatState -HeartbeatPath $heartbeat -ArmedPath $armed -Now $now
    Assert-Case 'legacy missing heartbeat is ignored until armed' (-not $state.Stale -and -not $state.Missing)

    Set-Content -LiteralPath $armed -Value 'armed'
    $state = Get-ReceiverHeartbeatState -HeartbeatPath $heartbeat -ArmedPath $armed -Now $now
    Assert-Case 'missing heartbeat receives install startup grace' (-not $state.Stale -and $state.StartingGrace)
    [IO.File]::SetLastWriteTime($armed, $now.AddMinutes(-6))
    $state = Get-ReceiverHeartbeatState -HeartbeatPath $heartbeat -ArmedPath $armed -Now $now
    Assert-Case 'armed missing heartbeat is unhealthy after startup grace' ($state.Stale -and $state.Missing)

    Set-Content -LiteralPath $heartbeat -Value 'alive'
    [IO.File]::SetLastWriteTime($heartbeat, $now.AddMinutes(-5))
    $state = Get-ReceiverHeartbeatState -HeartbeatPath $heartbeat -ArmedPath $armed -Now $now
    Assert-Case 'recent heartbeat remains healthy during quiet traffic' (-not $state.Stale -and -not $state.Missing)

    [IO.File]::SetLastWriteTime($heartbeat, $now.AddMinutes(-11))
    $state = Get-ReceiverHeartbeatState -HeartbeatPath $heartbeat -ArmedPath $armed -Now $now
    Assert-Case 'stale heartbeat is unhealthy' $state.Stale

    [IO.File]::SetLastWriteTime($armed, $now.AddMinutes(-1))
    $state = Get-ReceiverHeartbeatState -HeartbeatPath $heartbeat -ArmedPath $armed -Now $now
    Assert-Case 'stale old heartbeat is ignored during healthy startup grace' `
        (-not $state.Stale -and $state.StartingGrace)

    Assert-Case 'restart allowed when no cooldown marker exists' `
        (Test-ReceiverRestartCooldown -MarkerPath $restartMarker -Now $now -CooldownMinutes 30)
    Set-Content -LiteralPath $restartMarker -Value 'recent'
    [IO.File]::SetLastWriteTime($restartMarker, $now.AddMinutes(-10))
    Assert-Case 'restart suppressed inside cooldown' `
        (-not (Test-ReceiverRestartCooldown -MarkerPath $restartMarker -Now $now -CooldownMinutes 30))
    [IO.File]::SetLastWriteTime($restartMarker, $now.AddMinutes(-31))
    Assert-Case 'restart allowed after cooldown' `
        (Test-ReceiverRestartCooldown -MarkerPath $restartMarker -Now $now -CooldownMinutes 30)
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

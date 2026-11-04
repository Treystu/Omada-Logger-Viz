function Get-ReceiverHeartbeatState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$HeartbeatPath,
        [Parameter(Mandatory)][string]$ArmedPath,
        [datetime]$Now = (Get-Date),
        [int]$StaleMinutes = 10,
        [int]$StartupGraceMinutes = 5
    )

    $fi = Get-Item -LiteralPath $HeartbeatPath -ErrorAction SilentlyContinue
    $heartbeatExists = ($null -ne $fi)
    $armedItem = Get-Item -LiteralPath $ArmedPath -ErrorAction SilentlyContinue
    $armed = ($null -ne $armedItem)
    $missing = (-not $heartbeatExists -and $armed)
    $stale = $missing
    if ($heartbeatExists) {
        $stale = (($Now - $fi.LastWriteTime).TotalMinutes -gt $StaleMinutes)
    }
    $startingGrace = ($armedItem -and
        (($Now - $armedItem.LastWriteTime).TotalMinutes -lt $StartupGraceMinutes))
    if ($stale -and $startingGrace) { $stale = $false }

    [pscustomobject]@{
        HeartbeatExists = $heartbeatExists
        Armed = $armed
        Missing = $missing
        Stale = $stale
        StartingGrace = [bool]$startingGrace
    }
}

function Test-ReceiverRestartCooldown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$MarkerPath,
        [datetime]$Now = (Get-Date),
        [int]$CooldownMinutes = 30
    )

    $marker = Get-Item -LiteralPath $MarkerPath -ErrorAction SilentlyContinue
    if (-not $marker) { return $true }
    return (($Now - $marker.LastWriteTime).TotalMinutes -ge $CooldownMinutes)
}

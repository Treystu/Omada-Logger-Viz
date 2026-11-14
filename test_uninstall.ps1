$ErrorActionPreference = 'Stop'
function Assert-Case([string]$Name, [bool]$Condition) {
    if (-not $Condition) { throw "FAILED: $Name" }
    Write-Output "PASS: $Name"
}

$uninstallerPath = Join-Path $PSScriptRoot 'uninstall.ps1'
$tokens = $null; $parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($uninstallerPath, [ref]$tokens, [ref]$parseErrors) | Out-Null
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
. $uninstallerPath

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('omada-uninstall-test-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $script:InstallerRoot = $tempRoot
    foreach ($entry in @(
        @{ Name = 'omada_syslog.py'; Text = 'Omada syslog receiver' },
        @{ Name = 'watchdog.ps1'; Text = 'Omada Syslog Watchdog - keeps the receiver' },
        @{ Name = 'omada_viz.py'; Text = 'Omada syslog viz - local web UI' },
        @{ Name = 'viz.ps1'; Text = 'Omada Viz launcher - one click to the live traffic dashboard' }
    )) { Set-Content -LiteralPath (Join-Path $tempRoot $entry.Name) -Value $entry.Text }

    $receiver = [pscustomobject]@{
        Description = 'UDP/514 syslog receiver for TP-Link Omada ER8411 remote logging (per-user)'; State = 'Running'
        Actions = @([pscustomobject]@{ Execute = 'pythonw.exe'; Arguments = '"' + (Join-Path $tempRoot 'omada_syslog.py') + '" --log-file "C:\logs\firewall.log" --max-mb 100' })
    }
    $watchdog = [pscustomobject]@{
        Description = 'Keeps the receiver (heartbeat health) and viz (HTTP health) alive'; State = 'Ready'
        Actions = @([pscustomobject]@{ Execute = 'powershell.exe'; Arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $tempRoot 'watchdog.ps1') + '"' })
    }
    $viz = [pscustomobject]@{
        Description = 'Always-on localhost web UI for Omada Logger & Viz (http://localhost:8780)'; State = 'Ready'
        Actions = @([pscustomobject]@{ Execute = 'python.exe'; Arguments = '"' + (Join-Path $tempRoot 'omada_viz.py') + '" --port 8780' })
    }
    Assert-Case 'receiver task ownership requires the installer description, Python action, and source marker' (Test-ProductTask $receiver 'Receiver')
    Assert-Case 'watchdog task ownership recognizes a moved checkout through its source marker' (Test-ProductTask $watchdog 'Watchdog')
    $watchdog.Description = 'Restarts the receiver task if the raw log goes stale (hung process / post-sleep)'
    Assert-Case 'legacy watchdog description remains verifiable when its action and script marker match' (Test-ProductTask $watchdog 'Watchdog')
    $watchdog.Description = 'Keeps the receiver (heartbeat health) and viz (HTTP health) alive'
    Assert-Case 'Viz task ownership matches installer action and source marker' (Test-ProductTask $viz 'Viz')
    $foreign = $receiver.PSObject.Copy(); $foreign.Description = 'Unrelated task'
    Assert-Case 'same-named task with unrelated description is not owned' (-not (Test-ProductTask $foreign 'Receiver'))
    Set-Content -LiteralPath (Join-Path $tempRoot 'omada_syslog.py') -Value 'unrelated script'
    Assert-Case 'moved target without stable source marker is not owned' (-not (Test-ProductTask $receiver 'Receiver'))
    Set-Content -LiteralPath (Join-Path $tempRoot 'omada_syslog.py') -Value 'Omada syslog receiver'

    $desktopShortcut = [pscustomobject]@{ TargetPath = 'powershell.exe'; Description = 'Omada Logger & Viz - live traffic dashboard'; Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $tempRoot 'viz.ps1') + '"' }
    $startupShortcut = [pscustomobject]@{ TargetPath = 'pythonw.exe'; Description = 'Omada Logger & Viz - auto-start the traffic dashboard'; Arguments = '"' + (Join-Path $tempRoot 'omada_viz.py') + '" --port 8780' }
    Assert-Case 'desktop shortcut ownership includes launcher marker' (Test-ProductShortcut $desktopShortcut 'Desktop')
    Assert-Case 'startup shortcut ownership includes Viz script marker' (Test-ProductShortcut $startupShortcut 'Startup')
    $desktopShortcut.Description = 'Unrelated shortcut'
    Assert-Case 'same-named shortcut with unrelated description is not owned' (-not (Test-ProductShortcut $desktopShortcut 'Desktop'))
    $desktopShortcut.Description = 'Omada Logger & Viz - live traffic dashboard'

    # Distinguish a genuinely absent shortcut from an existing but unreadable
    # one without invoking the Windows Script Host COM server.
    function Get-Item { param($LiteralPath, [switch]$Force, $ErrorAction); throw [System.Management.Automation.ItemNotFoundException]::new('missing') }
    $missingShortcut = Get-ShortcutInfo (Join-Path $tempRoot 'missing.lnk')
    Assert-Case 'missing shortcut is treated as absent' ($null -eq $missingShortcut)
    function Get-Item { param($LiteralPath, [switch]$Force, $ErrorAction); [pscustomobject]@{ FullName = $LiteralPath } }
    function New-Object { param($ComObject, $ArgumentList); throw 'mock COM read denied' }
    $comMessage = ''
    try { Get-ShortcutInfo (Join-Path $tempRoot 'unreadable.lnk') } catch { $comMessage = $_.Exception.Message }
    Assert-Case 'shortcut COM read failure stops with guidance before mutation' ($comMessage -match 'Could not read shortcut' -and $comMessage -match 'no uninstall changes were made')
    Remove-Item Function:\Get-Item, Function:\New-Object

    $goodRule = [pscustomobject]@{ Direction = 'Inbound'; Action = 'Allow'; Profile = @('Private', 'Domain'); Protocol = 'UDP'; LocalPort = '514'; RemoteAddress = @('192.168.0.0/24') }
    function Get-NetFirewallPortFilter { param([Parameter(ValueFromPipeline)]$InputObject); process { [pscustomobject]@{ Protocol = $InputObject.Protocol; LocalPort = $InputObject.LocalPort } } }
    function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline)]$InputObject); process { [pscustomobject]@{ RemoteAddress = $InputObject.RemoteAddress } } }
    Assert-Case 'firewall rule matches install protocol, port, remote subnet, direction, action, profiles' (Test-ProductFirewallRule $goodRule)
    $badRule = $goodRule.PSObject.Copy(); $badRule.RemoteAddress = @('Any')
    Assert-Case 'same-named broad firewall rule is not owned' (-not (Test-ProductFirewallRule $badRule))

    # Exercise the plan and mutations entirely through mocks; no live tasks,
    # firewall rules, shortcuts, or user data are touched.
    $script:mockTasks = @{
        'Omada Syslog Receiver' = $receiver
        'Omada Syslog Watchdog' = $watchdog
        'Omada Viz Server' = $viz
    }
    $script:mockShortcuts = @{ Desktop = $desktopShortcut; Startup = $startupShortcut }
    $script:mockRules = @($goodRule)
    $script:uninstallCalls = [System.Collections.Generic.List[string]]::new()
    function Get-ScheduledTask { param($TaskName, $ErrorAction); if ($script:mockTasks.ContainsKey($TaskName)) { return $script:mockTasks[$TaskName] }; throw [System.Management.Automation.ItemNotFoundException]::new('missing') }
    function Get-ShortcutInfo { param($Path); if ($Path -like '*Startup*') { return $script:mockShortcuts.Startup }; return $script:mockShortcuts.Desktop }
    function Get-NetFirewallRule { param($DisplayName, $ErrorAction); return $script:mockRules }
    $script:failStopName = ''
    function Stop-ScheduledTask { param($TaskName, $ErrorAction); $script:uninstallCalls.Add("stop:$TaskName"); if ($TaskName -eq $script:failStopName) { throw 'mock stop failure' } }
    function Unregister-ScheduledTask { param($TaskName, $Confirm, $ErrorAction); $script:uninstallCalls.Add("unregister:$TaskName") }
    function Test-Path { param($LiteralPath, $PathType); if ($LiteralPath -like '*Omada Viz.lnk') { return $false }; if ($PathType) { Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType } else { Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath } }
    function Remove-Item { param($LiteralPath, [switch]$Force, $ErrorAction, [switch]$Recurse); $script:uninstallCalls.Add("remove:$LiteralPath"); if ($LiteralPath -eq (Join-Path $env:LOCALAPPDATA 'OmadaSyslog')) { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Recurse -Force } }
    function Remove-NetFirewallRule { param($InputObject, $ErrorAction); $script:uninstallCalls.Add('firewall') }
    $plan = Get-UninstallPlan
    Assert-Case 'complete verified resource set is preflighted before mutation' ($plan.Tasks.Count -eq 3 -and $plan.Shortcuts.Count -eq 2 -and $plan.FirewallRules.Count -eq 1 -and $script:uninstallCalls.Count -eq 0)
    Invoke-ProductUninstall -Plan $plan
    Assert-Case 'default uninstall never purges log data' (-not ($script:uninstallCalls | Where-Object { $_ -like '*OmadaSyslog*' }))
    Assert-Case 'mock uninstall removes verified resources only' ($script:uninstallCalls.Count -eq 7)

    $script:uninstallCalls.Clear()
    $script:failStopName = 'Omada Syslog Watchdog'
    $partialMessage = ''
    try {
        Invoke-ProductUninstall -Plan ([pscustomobject]@{ Tasks = @(
            [pscustomobject]@{ Name = 'Omada Syslog Receiver'; State = 'Running' },
            [pscustomobject]@{ Name = 'Omada Syslog Watchdog'; State = 'Running' }
        ); Shortcuts = @(); FirewallRules = @() })
    } catch { $partialMessage = $_.Exception.Message }
    Assert-Case 'partial failure reports completed and failed operations with safe rerun guidance' ($partialMessage -match "Completed operations: stopping task 'Omada Syslog Receiver'" -and $partialMessage -match "stopping task 'Omada Syslog Watchdog'" -and $partialMessage -match 'No rollback was attempted' -and $partialMessage -match 'rerun uninstall')
    $script:failStopName = ''

    $script:mockTasks['Omada Syslog Receiver'] = $foreign
    $script:uninstallCalls.Clear()
    $message = ''
    try { Get-UninstallPlan } catch { $message = $_.Exception.Message }
    Assert-Case 'unknown same-named task fails closed before any resource changes' ($message -match 'ownership cannot be verified' -and $script:uninstallCalls.Count -eq 0)

    # Purge path safety is checked before recursive deletion and uses only a
    # temporary directory by overriding LOCALAPPDATA for this fixture.
    $priorLocal = $env:LOCALAPPDATA
    try {
        $env:LOCALAPPDATA = $tempRoot
        $logFixture = Join-Path $tempRoot 'OmadaSyslog'
        $outsideFixture = Join-Path $tempRoot 'OutsideFixture'
        New-Item -ItemType Directory -Path $logFixture, $outsideFixture | Out-Null
        $outsideSentinel = Join-Path $outsideFixture 'keep.txt'
        Set-Content -LiteralPath $outsideSentinel -Value 'keep'
        $junctionPath = Join-Path $logFixture 'mock-outside-link'
        $script:enumeratedDirectories = [System.Collections.Generic.List[string]]::new()
        function Test-Path { param($LiteralPath, $PathType); if ($PathType) { Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType } else { Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath } }
        function Get-Item {
            param($LiteralPath, [switch]$Force, $ErrorAction)
            if ($LiteralPath -eq $logFixture) { return [pscustomobject]@{ Attributes = [IO.FileAttributes]::Directory; PSIsContainer = $true } }
            if ($LiteralPath -eq $junctionPath) { return [pscustomobject]@{ Attributes = [IO.FileAttributes]::ReparsePoint; PSIsContainer = $true } }
            Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force -ErrorAction $ErrorAction
        }
        function Get-PurgeDirectoryChildren { param($Directory); $script:enumeratedDirectories.Add($Directory); if ($Directory -eq $logFixture) { return @($junctionPath) }; return @() }
        $reparseMessage = ''
        try { Test-NoReparsePoints $logFixture } catch { $reparseMessage = $_.Exception.Message }
        Assert-Case 'nested junction is rejected before following or deleting its target' ($reparseMessage -match 'reparse point' -and $script:enumeratedDirectories.Count -eq 1 -and (Microsoft.PowerShell.Management\Test-Path -LiteralPath $outsideSentinel))
        Microsoft.PowerShell.Management\Remove-Item Function:\Get-Item, Function:\Get-PurgeDirectoryChildren
        function Get-PurgeDirectoryChildren { param($Directory); [IO.Directory]::GetFileSystemEntries($Directory) }
        function Test-Path { param($LiteralPath, $PathType); if ($LiteralPath -like '*Omada Viz.lnk') { return $false }; if ($PathType) { Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType } else { Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath } }
        $script:uninstallCalls.Clear()
        Invoke-ProductUninstall -Plan ([pscustomobject]@{ Tasks = @(); Shortcuts = @(); FirewallRules = @() }) -PurgeLogs
        Assert-Case 'explicit purge targets only the expected OmadaSyslog child folder' ($script:uninstallCalls.Count -eq 1 -and $script:uninstallCalls[0] -eq "remove:$(Join-Path $tempRoot 'OmadaSyslog')")
    } finally { $env:LOCALAPPDATA = $priorLocal }

    $script:entryCalls = [System.Collections.Generic.List[string]]::new()
    $script:entryPurgeFailure = $false
    $script:entryPlanFailure = $false
    $script:entryStartFailure = $false
    $script:entryExitCode = 0
    $script:entryLaunchArgs = @()
    function Invoke-ProductUninstall { param($Plan, [switch]$PurgeLogs); $script:entryCalls.Add($(if ($PurgeLogs) { 'purge' } else { 'uninstall' })); if ($PurgeLogs -and $script:entryPurgeFailure) { throw 'mock purge failure' } }
    function Get-UninstallPlan { $script:entryCalls.Add('plan'); if ($script:entryPlanFailure) { throw 'mock preflight conflict' }; [pscustomobject]@{ Tasks = @(); Shortcuts = @(); FirewallRules = @() } }
    function Start-Process { param($FilePath, $ArgumentList, $Verb, [switch]$Wait, [switch]$PassThru, $ErrorAction); $script:entryCalls.Add('start'); $script:entryLaunchArgs = @($ArgumentList); if ($script:entryStartFailure) { throw 'mock UAC canceled' }; [pscustomobject]@{ ExitCode = $script:entryExitCode } }

    $script:entryCalls.Clear()
    Invoke-UninstallerEntry -IsAdmin:$false -PurgeLogs
    Assert-Case 'unelevated explicit purge preflights, runs exactly once before UAC launch, and is not forwarded' ($script:entryCalls.Count -eq 3 -and $script:entryCalls[0] -eq 'plan' -and $script:entryCalls[1] -eq 'purge' -and $script:entryCalls[2] -eq 'start' -and $script:entryLaunchArgs -notcontains '-PurgeLogs')

    $script:entryCalls.Clear()
    $alreadyElevatedMessage = ''
    try { Invoke-UninstallerEntry -IsAdmin:$true -PurgeLogs } catch { $alreadyElevatedMessage = $_.Exception.Message }
    Assert-Case 'already elevated explicit purge aborts without purge or task operations' ($script:entryCalls.Count -eq 0 -and $alreadyElevatedMessage -match 'unelevated PowerShell')

    $script:entryCalls.Clear(); $script:entryPurgeFailure = $true
    $purgeFailureMessage = ''
    try { Invoke-UninstallerEntry -IsAdmin:$false -PurgeLogs } catch { $purgeFailureMessage = $_.Exception.Message }
    Assert-Case 'purge failure prevents elevation launch' ($script:entryCalls.Count -eq 2 -and $script:entryCalls[0] -eq 'plan' -and $script:entryCalls[1] -eq 'purge' -and $purgeFailureMessage -match 'mock purge failure')
    $script:entryPurgeFailure = $false

    $script:entryCalls.Clear(); $script:entryPlanFailure = $true
    $preflightFailureMessage = ''
    try { Invoke-UninstallerEntry -IsAdmin:$false -PurgeLogs } catch { $preflightFailureMessage = $_.Exception.Message }
    Assert-Case 'ownership preflight failure prevents purge and elevation' ($script:entryCalls.Count -eq 1 -and $script:entryCalls[0] -eq 'plan' -and $preflightFailureMessage -match 'mock preflight conflict')
    $script:entryPlanFailure = $false

    $script:entryCalls.Clear(); $script:entryStartFailure = $true
    $uacFailureMessage = ''
    try { Invoke-UninstallerEntry -IsAdmin:$false -PurgeLogs } catch { $uacFailureMessage = $_.Exception.Message }
    Assert-Case 'UAC cancellation after purge explains that logs are gone and system resources remain' ($uacFailureMessage -match 'log purge already completed' -and $uacFailureMessage -match 'Windows resources were not removed' -and $script:entryCalls.Count -eq 3 -and $script:entryCalls[0] -eq 'plan' -and $script:entryCalls[1] -eq 'purge' -and $script:entryCalls[2] -eq 'start')
    $script:entryStartFailure = $false

    $script:entryCalls.Clear(); $script:entryExitCode = 1
    $purgeChildFailureMessage = ''
    try { Invoke-UninstallerEntry -IsAdmin:$false -PurgeLogs } catch { $purgeChildFailureMessage = $_.Exception.Message }
    Assert-Case 'nonzero elevated child status reports purge completion and possible partial resource removal' ($purgeChildFailureMessage -match 'log purge already completed' -and $purgeChildFailureMessage -match 'exited with code 1' -and $purgeChildFailureMessage -match 'may be partially removed' -and $purgeChildFailureMessage -match 'without -PurgeLogs')

    $script:entryCalls.Clear()
    $defaultChildFailureMessage = ''
    try { Invoke-UninstallerEntry -IsAdmin:$false } catch { $defaultChildFailureMessage = $_.Exception.Message }
    Assert-Case 'nonzero elevated child status is reported on default no-purge uninstall' ($defaultChildFailureMessage -match 'exited with code 1' -and $defaultChildFailureMessage -match 'may be partially removed' -and $defaultChildFailureMessage -notmatch 'log purge already completed')
    $script:entryExitCode = 0

    $script:entryCalls.Clear()
    Invoke-UninstallerEntry -IsAdmin:$false
    Assert-Case 'default unelevated uninstall launches elevation without purging or forwarding flag' ($script:entryCalls.Count -eq 1 -and $script:entryCalls[0] -eq 'start' -and $script:entryLaunchArgs -notcontains '-PurgeLogs')

    $script:entryCalls.Clear()
    Invoke-UninstallerEntry -IsAdmin:$true
    Assert-Case 'default elevated uninstall still plans and removes verified Windows resources without purge' ($script:entryCalls.Count -eq 2 -and $script:entryCalls[0] -eq 'plan' -and $script:entryCalls[1] -eq 'uninstall')
}
finally { Microsoft.PowerShell.Management\Remove-Item -LiteralPath $tempRoot -Recurse -Force }

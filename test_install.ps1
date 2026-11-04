$ErrorActionPreference = 'Stop'

function Assert-Case([string]$Name, [bool]$Condition) {
    if (-not $Condition) { throw "FAILED: $Name" }
    Write-Output "PASS: $Name"
}

$installerPath = Join-Path $PSScriptRoot 'install.ps1'
$script:InstallerRoot = $PSScriptRoot
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $installerPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }

# Load only the installer helpers; never execute its task/firewall setup body.
$helperNames = @(
    'ConvertTo-PowerShellLiteral',
    'Get-ElevatedRelaunchArguments',
    'Get-VizBootTask',
    'Test-VizBootTaskOwned',
    'Get-VizStartupShortcut',
    'Get-VizDesktopShortcut',
    'Test-VizStartupShortcutOwned',
    'Test-VizDesktopShortcutOwned',
    'Test-RecognizedProductScript',
    'Test-InstallerResourceConflicts',
    'Remove-VizBootTask',
    'Remove-VizStartupShortcut',
    'New-VizStartupShortcut',
    'New-VizDesktopShortcut',
    'Register-VizBootTask',
    'Set-VizStartupMode',
    'Test-InstallerPayload'
)
foreach ($name in $helperNames) {
    $functionAst = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $name
    }, $true)
    if (-not $functionAst) { throw "Missing helper function: $name" }
    Invoke-Expression $functionAst.Extent.Text
}

# Exercise the same encoded child invocation used for UAC relaunch, but target
# a temporary probe script so no installer side effects can occur.
$tempDir = Join-Path ([IO.Path]::GetTempPath()) ('omada-install-test-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tempDir | Out-Null
try {
    $probe = Join-Path $tempDir 'probe script.ps1'
    @'
param([string]$TaskArgs = '', [switch]$VizBoot)
[pscustomobject]@{ TaskArgs = $TaskArgs; VizBoot = [bool]$VizBoot } | ConvertTo-Json -Compress
'@ | Set-Content -LiteralPath $probe -Encoding UTF8

    $taskArgs = '--log-file "D:\Omada Logs\firewall & events.log" --label "router''s primary"'
    $relaunch = Get-ElevatedRelaunchArguments -ScriptPath $probe -TaskArgs $taskArgs -VizBoot
    $ProgressPreference = 'SilentlyContinue'
    $childOutput = & powershell.exe @relaunch
    if ($LASTEXITCODE -ne 0) { throw 'Encoded UAC child invocation failed.' }
    $captured = ($childOutput -join "`n") | ConvertFrom-Json
    Assert-Case 'self-elevation preserves TaskArgs spaces, embedded quotes, apostrophes, and ampersands' `
        ($captured.TaskArgs -ceq $taskArgs)
    Assert-Case 'self-elevation preserves VizBoot switch' ([bool]$captured.VizBoot)

    # Payload preflight must fail before an installer can prompt for elevation
    # or perform any scheduled-task/firewall operations.
    $payloadRoot = Join-Path $tempDir 'payload'
    New-Item -ItemType Directory -Path $payloadRoot | Out-Null
    $required = @('omada_syslog.py', 'omada_event_store.py', 'omada_condenser.py',
        'watchdog.ps1', 'watchdog-health.ps1', 'omada_viz.py', 'viz.html', 'viz.ps1')
    foreach ($file in $required) { Set-Content -LiteralPath (Join-Path $payloadRoot $file) -Value 'stub' }
    Remove-Item -LiteralPath (Join-Path $payloadRoot 'omada_event_store.py')
    Remove-Item -LiteralPath (Join-Path $payloadRoot 'watchdog-health.ps1')
    $script:preflightSideEffects = 0
    function New-NetFirewallRule { $script:preflightSideEffects++ }
    function Register-ScheduledTask { $script:preflightSideEffects++ }
    function Start-ScheduledTask { $script:preflightSideEffects++ }
    $missingMessage = ''
    try { Test-InstallerPayload -Root $payloadRoot } catch { $missingMessage = $_.Exception.Message }
    Assert-Case 'preflight lists missing required runtime module and watchdog helper' `
        ($missingMessage -match 'omada_event_store\.py' -and $missingMessage -match 'watchdog-health\.ps1')
    Assert-Case 'failed payload preflight performs no firewall or task operations' `
        ($script:preflightSideEffects -eq 0 -and $missingMessage -match 'No system changes were made')
    foreach ($file in @('omada_event_store.py', 'watchdog-health.ps1')) {
        Set-Content -LiteralPath (Join-Path $payloadRoot $file) -Value 'stub'
    }
    Test-InstallerPayload -Root $payloadRoot
    Assert-Case 'complete runtime payload passes preflight' $true

    # Replace all OS-facing operations with in-memory mocks. Ownership checks
    # use realistic task actions and shortcut properties.
    $script:modeState = @{ Shortcut = $null; Desktop = $null; BootTask = $null }
    $script:modeCalls = @{ CreateShortcut = 0; RemoveShortcut = 0; RegisterTask = 0; RemoveTask = 0 }
    $script:failure = ''
    $script:accessFailure = $false
    function Get-VizBootTask {
        if ($script:accessFailure) { throw 'mock access denied reading scheduled task' }
        return $script:modeState.BootTask
    }
    function Get-VizStartupShortcut([string]$StartupShortcut) { return $script:modeState.Shortcut }
    function Get-VizDesktopShortcut([string]$DesktopShortcut) { return $script:modeState.Desktop }
    function Remove-VizStartupShortcut([string]$StartupShortcut) {
        if ($script:failure -eq 'remove-shortcut') { throw 'mock shortcut removal failure' }
        $script:modeCalls.RemoveShortcut++
        $script:modeState.Shortcut = $null
    }
    function New-VizStartupShortcut {
        param([string]$StartupShortcut, [string]$Python, [string]$VizScript, [string]$WorkingDirectory)
        if ($script:failure -eq 'create-shortcut') { throw 'mock shortcut creation failure' }
        $script:modeCalls.CreateShortcut++
        $script:modeState.Shortcut = [pscustomobject]@{
            TargetPath = $Python
            Arguments = '"' + $VizScript + '" --port 8780'
            Description = 'Omada Logger & Viz - auto-start the traffic dashboard'
        }
    }
    function Register-VizBootTask {
        param([string]$Python, [string]$VizScript, [string]$WorkingDirectory)
        if ($script:failure -eq 'register-task') { throw 'mock task registration failure' }
        $script:modeCalls.RegisterTask++
        $script:modeState.BootTask = [pscustomobject]@{ Description = 'Always-on localhost web UI for Omada Logger & Viz'; Actions = @([pscustomobject]@{
            Execute = $Python; Arguments = '"' + $VizScript + '" --port 8780'
        }) }
    }
    function Remove-VizBootTask {
        if ($script:failure -eq 'remove-task') { throw 'mock task removal failure' }
        $script:modeCalls.RemoveTask++
        $script:modeState.BootTask = $null
    }

    $modeArgs = @{
        Python = 'pythonw.exe'; VizScript = (Join-Path $PSScriptRoot 'omada_viz.py')
        StartupShortcut = 'C:\profile\Startup\Omada Viz.lnk'; WorkingDirectory = 'C:\app'
    }
    # Existing default mode -> boot task mode, then repeat to prove convergence.
    Set-VizStartupMode @modeArgs
    Set-VizStartupMode -VizBoot @modeArgs
    Assert-Case 'default to VizBoot removes the Startup shortcut and registers only the boot task' `
        (-not $script:modeState.Shortcut -and [bool]$script:modeState.BootTask)
    Set-VizStartupMode -VizBoot @modeArgs
    Assert-Case 'repeating VizBoot remains in boot-task-only mode' `
        (-not $script:modeState.Shortcut -and [bool]$script:modeState.BootTask)

    # Existing boot task -> default mode, then repeat to prove convergence.
    Set-VizStartupMode @modeArgs
    Assert-Case 'VizBoot to default removes the boot task and creates only the Startup shortcut' `
        ([bool]$script:modeState.Shortcut -and -not $script:modeState.BootTask)
    Set-VizStartupMode @modeArgs
    Assert-Case 'repeating default install remains in shortcut-only mode' `
        ([bool]$script:modeState.Shortcut -and -not $script:modeState.BootTask)
    Assert-Case 'only the named Omada Viz startup mechanism was reconciled' `
        ($script:modeCalls.RemoveShortcut -eq 1 -and $script:modeCalls.RemoveTask -eq 1)

    # Same-named unrelated resources must fail before replacing either one.
    $script:modeState.BootTask = [pscustomobject]@{ Actions = @([pscustomobject]@{
        Execute = 'powershell.exe'; Arguments = '-File unrelated.ps1'
    }) }
    $priorCreates = $script:modeCalls.CreateShortcut
    $message = ''
    try { Set-VizStartupMode @modeArgs } catch { $message = $_.Exception.Message }
    Assert-Case 'unrelated same-name task is preserved and blocks mode switch' `
        ($message -match 'not a verifiable' -and $script:modeCalls.CreateShortcut -eq $priorCreates)
    $script:modeState.BootTask = $null
    $script:modeState.Shortcut = [pscustomobject]@{
        TargetPath = 'wscript.exe'; Arguments = 'unrelated.vbs'; Description = 'unrelated'
    }
    $priorRegistrations = $script:modeCalls.RegisterTask
    $message = ''
    try { Set-VizStartupMode -VizBoot @modeArgs } catch { $message = $_.Exception.Message }
    Assert-Case 'unrelated same-name shortcut is preserved and blocks mode switch' `
        ($message -match 'does not match' -and $script:modeCalls.RegisterTask -eq $priorRegistrations)

    # Cleanup failure must roll back the newly provisioned alternative while
    # retaining the previous startup resource.
    $script:modeState.Shortcut = [pscustomobject]@{
        TargetPath = 'pythonw.exe'; Arguments = '"' + $modeArgs.VizScript + '" --port 8780'
        Description = 'Omada Logger & Viz - auto-start the traffic dashboard'
    }
    $script:failure = 'remove-shortcut'
    $message = ''
    try { Set-VizStartupMode -VizBoot @modeArgs } catch { $message = $_.Exception.Message }
    Assert-Case 'failed default-to-VizBoot cleanup rolls back new task and keeps old shortcut' `
        ($message -match 'prior startup remains available' -and -not $script:modeState.BootTask -and [bool]$script:modeState.Shortcut)
    $script:failure = ''
    $script:modeState.Shortcut = $null
    $script:modeState.BootTask = [pscustomobject]@{ Description = 'Always-on localhost web UI for Omada Logger & Viz'; Actions = @([pscustomobject]@{
        Execute = 'pythonw.exe'; Arguments = '"' + $modeArgs.VizScript + '" --port 8780'
    }) }
    $script:failure = 'remove-task'
    $message = ''
    try { Set-VizStartupMode @modeArgs } catch { $message = $_.Exception.Message }
    Assert-Case 'failed VizBoot-to-default cleanup rolls back new shortcut and keeps old task' `
        ($message -match 'prior startup remains available' -and -not $script:modeState.Shortcut -and [bool]$script:modeState.BootTask)

    # The action must point to a readable source file with the product marker;
    # same basename/arguments alone and multi-action tasks are not ownership.
    $unrelatedDir = Join-Path $tempDir 'unrelated'
    New-Item -ItemType Directory -Path $unrelatedDir | Out-Null
    $lookalikeScript = Join-Path $unrelatedDir 'omada_viz.py'
    Set-Content -LiteralPath $lookalikeScript -Value 'print("not Omada Viz")'
    $unrelatedTask = [pscustomobject]@{ Description = 'Always-on localhost web UI for Omada Logger & Viz'; Actions = @([pscustomobject]@{
        Execute = 'pythonw.exe'; Arguments = '"' + $lookalikeScript + '" --port 8780'
    }) }
    Assert-Case 'lookalike same-named Python script without the product marker is not owned' `
        (-not (Test-VizBootTaskOwned $unrelatedTask))
    $multiActionTask = [pscustomobject]@{ Description = 'Always-on localhost web UI for Omada Logger & Viz'; Actions = @(
        [pscustomobject]@{ Execute = 'pythonw.exe'; Arguments = '"' + $modeArgs.VizScript + '" --port 8780' },
        [pscustomobject]@{ Execute = 'powershell.exe'; Arguments = '-File unrelated.ps1' }
    ) }
    Assert-Case 'multi-action same-name task is not recognized as owned' `
        (-not (Test-VizBootTaskOwned $multiActionTask))
    $movedDir = Join-Path $tempDir 'moved-checkout'
    New-Item -ItemType Directory -Path $movedDir | Out-Null
    $movedScript = Join-Path $movedDir 'omada_viz.py'
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'omada_viz.py') -Destination $movedScript
    $movedTask = [pscustomobject]@{ Description = 'Always-on localhost web UI for Omada Logger & Viz'; Actions = @([pscustomobject]@{
        Execute = 'pythonw.exe'; Arguments = '"' + $movedScript + '" --port 8780'
    }) }
    Assert-Case 'relocated existing project script with product marker is recognized' (Test-VizBootTaskOwned $movedTask)
    $legacyTask = [pscustomobject]@{ Actions = @([pscustomobject]@{
        Execute = 'pythonw.exe'; Arguments = '"' + (Join-Path $PSScriptRoot 'omada_viz.py') + '" --port 8780'
    }) }
    Assert-Case 'historical task without a description is accepted with exact action and product source marker' `
        (Test-VizBootTaskOwned $legacyTask)
    $legacyShortcut = [pscustomobject]@{
        TargetPath = 'C:\Python\pythonw.exe'
        Arguments = '"' + (Join-Path $PSScriptRoot 'omada_viz.py') + '" --port 8780'
        Description = 'Omada Logger & Viz - auto-start the traffic dashboard'
    }
    Assert-Case 'historical Startup shortcut remains recognizable' (Test-VizStartupShortcutOwned $legacyShortcut)
    $ownedDesktop = [pscustomobject]@{
        TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $PSScriptRoot 'viz.ps1') + '"'
        Description = 'Omada Logger & Viz - live traffic dashboard'
    }
    Assert-Case 'existing product Desktop shortcut is recognizable' (Test-VizDesktopShortcutOwned $ownedDesktop)

    # Conflicts are checked before any task/firewall actions. The desktop link
    # has its own independent name and ownership test.
    $script:modeState.BootTask = $null
    $script:modeState.Shortcut = $null
    $script:modeState.Desktop = [pscustomobject]@{
        TargetPath = 'powershell.exe'; Arguments = '-File unrelated.ps1'; Description = 'Other application'
    }
    $priorActionCalls = $script:modeCalls.RegisterTask + $script:modeCalls.CreateShortcut +
        $script:modeCalls.RemoveTask + $script:modeCalls.RemoveShortcut + $script:preflightSideEffects
    $message = ''
    try { Test-InstallerResourceConflicts -StartupShortcut $modeArgs.StartupShortcut -DesktopShortcut 'C:\profile\Desktop\Omada Viz.lnk' } catch { $message = $_.Exception.Message }
    Assert-Case 'unrelated Desktop Omada Viz shortcut is preserved and blocks before installer actions' `
        ($message -match 'Desktop shortcut' -and $script:modeCalls.RegisterTask + $script:modeCalls.CreateShortcut +
            $script:modeCalls.RemoveTask + $script:modeCalls.RemoveShortcut + $script:preflightSideEffects -eq $priorActionCalls)

    $script:modeState.Desktop = $null
    $script:accessFailure = $true
    $priorActionCalls = $script:modeCalls.RegisterTask + $script:modeCalls.CreateShortcut +
        $script:modeCalls.RemoveTask + $script:modeCalls.RemoveShortcut + $script:preflightSideEffects
    $message = ''
    try { Test-InstallerResourceConflicts -StartupShortcut $modeArgs.StartupShortcut -DesktopShortcut 'C:\profile\Desktop\Omada Viz.lnk' } catch { $message = $_.Exception.Message }
    $script:accessFailure = $false
    Assert-Case 'inaccessible task configuration fails closed before installer actions' `
        ($message -match 'mock access denied' -and $script:modeCalls.RegisterTask + $script:modeCalls.CreateShortcut +
            $script:modeCalls.RemoveTask + $script:modeCalls.RemoveShortcut + $script:preflightSideEffects -eq $priorActionCalls)

    $installText = Get-Content -LiteralPath $installerPath -Raw
    $ownershipCheckAt = $installText.IndexOf('Test-InstallerResourceConflicts -StartupShortcut $startupShortcut')
    $logDirectoryCreateAt = $installText.IndexOf('New-Item -ItemType Directory -Force -Path $LogDir')
    $firewallCreateAt = $installText.IndexOf('New-NetFirewallRule -DisplayName $RuleName')
    Assert-Case 'resource conflict preflight appears before log, firewall, and task mutations' `
        ($ownershipCheckAt -ge 0 -and $ownershipCheckAt -lt $logDirectoryCreateAt -and $ownershipCheckAt -lt $firewallCreateAt)
} finally {
    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

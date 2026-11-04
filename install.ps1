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
    [string]$TaskArgs = '',
    [switch]$VizBoot
)

$ErrorActionPreference = 'Stop'
$TaskName = 'Omada Syslog Receiver'
$RuleName = 'Omada Syslog UDP 514 inbound'
$LogDir   = Join-Path $env:LOCALAPPDATA 'OmadaSyslog'
$Subnet   = '192.168.0.0/24'
$script:InstallerRoot = $PSScriptRoot

function ConvertTo-PowerShellLiteral([string]$Value) {
    "'" + $Value.Replace("'", "''") + "'"
}

function Get-ElevatedRelaunchArguments {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [string]$TaskArgs = '',
        [switch]$VizBoot
    )

    # Encode the child invocation so Start-Process never has to reconstruct
    # quoting for TaskArgs (which is itself a command-line fragment).
    $command = '& ' + (ConvertTo-PowerShellLiteral $ScriptPath)
    if ($TaskArgs) {
        $command += ' -TaskArgs ' + (ConvertTo-PowerShellLiteral $TaskArgs)
    }
    if ($VizBoot) { $command += ' -VizBoot' }
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
}

function Get-VizBootTask {
    try {
        Get-ScheduledTask -TaskName 'Omada Viz Server' -ErrorAction Stop
    }
    catch {
        if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound) { return $null }
        throw "Could not inspect scheduled task 'Omada Viz Server'; no installer changes were made. $($_.Exception.Message)"
    }
}

function Remove-VizBootTask {
    $task = Get-VizBootTask
    if (-not $task) { return }
    if (-not (Test-VizBootTaskOwned $task)) {
        throw "Task 'Omada Viz Server' is not a verifiable Omada Viz task; leaving it untouched. Check its single action, target script, and description before retrying."
    }
    if ($task.State -eq 'Running') {
        Stop-ScheduledTask -TaskName 'Omada Viz Server' -ErrorAction Stop
    }
    Unregister-ScheduledTask -TaskName 'Omada Viz Server' -Confirm:$false -ErrorAction Stop
}

function Remove-VizStartupShortcut([string]$StartupShortcut) {
    $shortcut = Get-VizStartupShortcut $StartupShortcut
    if (-not $shortcut) { return }
    if (-not (Test-VizStartupShortcutOwned $shortcut)) {
        throw "Startup shortcut '$StartupShortcut' exists but does not match the Omada Viz launcher; leaving it untouched."
    }
    Remove-Item -LiteralPath $StartupShortcut -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $StartupShortcut) {
        throw "Could not remove the Omada Viz startup shortcut at '$StartupShortcut'."
    }
}

function Get-VizStartupShortcut([string]$ShortcutPath) {
    try { Get-Item -LiteralPath $ShortcutPath -ErrorAction Stop | Out-Null }
    catch [System.Management.Automation.ItemNotFoundException] { return $null }
    catch [System.IO.FileNotFoundException] { return $null }
    catch [System.IO.DirectoryNotFoundException] { return $null }
    catch { throw "Could not inspect shortcut '$ShortcutPath'; no installer changes were made. $($_.Exception.Message)" }
    try {
        $ws = New-Object -ComObject WScript.Shell
        $ws.CreateShortcut($ShortcutPath)
    }
    catch { throw "Could not read shortcut '$ShortcutPath'; no installer changes were made. $($_.Exception.Message)" }
}

function Get-VizDesktopShortcut([string]$ShortcutPath) {
    Get-VizStartupShortcut $ShortcutPath
}

function Test-RecognizedProductScript([string]$Path, [string]$ExpectedPath, [string]$Marker) {
    try { $fullPath = [IO.Path]::GetFullPath($Path) }
    catch { return $false }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { return $false }
    try { $content = Get-Content -LiteralPath $fullPath -Raw -ErrorAction Stop }
    catch { throw "Could not inspect launcher target '$fullPath'; leaving the existing resource untouched. $($_.Exception.Message)" }
    if ($fullPath.Equals([IO.Path]::GetFullPath($ExpectedPath), [StringComparison]::OrdinalIgnoreCase)) {
        return ($content.Contains($Marker))
    }
    # A moved checkout is recognizable only while its old target remains
    # readable and still carries the product's stable source marker.
    return $content.Contains($Marker)
}

function Test-VizBootTaskOwned($Task) {
    if (-not $Task -or @($Task.Actions).Count -ne 1) { return $false }
    if ($Task.Description -and [string]$Task.Description -notmatch 'Omada Logger & Viz') { return $false }
    $action = @($Task.Actions)[0]
    $exe = [IO.Path]::GetFileName([string]$action.Execute)
    if ($exe -notin @('python.exe', 'pythonw.exe')) { return $false }
    $argsMatch = [regex]::Match([string]$action.Arguments,
        '(?i)^\s*"(?<script>[^"\r\n]+[\\/]omada_viz\.py)"\s+--port\s+8780\s*$')
    if (-not $argsMatch.Success) { return $false }
    $expected = Join-Path $script:InstallerRoot 'omada_viz.py'
    return Test-RecognizedProductScript -Path $argsMatch.Groups['script'].Value -ExpectedPath $expected `
        -Marker 'Omada syslog viz - local web UI'
}

function Test-VizStartupShortcutOwned($Shortcut) {
    if (-not $Shortcut) { return $false }
    $exe = [IO.Path]::GetFileName([string]$Shortcut.TargetPath)
    if ($exe -notin @('python.exe', 'pythonw.exe')) { return $false }
    if ($Shortcut.Description -and [string]$Shortcut.Description -ne 'Omada Logger & Viz - auto-start the traffic dashboard') { return $false }
    $argsMatch = [regex]::Match([string]$Shortcut.Arguments,
        '(?i)^\s*"(?<script>[^"\r\n]+[\\/]omada_viz\.py)"\s+--port\s+8780\s*$')
    if (-not $argsMatch.Success) { return $false }
    $expected = Join-Path $script:InstallerRoot 'omada_viz.py'
    return Test-RecognizedProductScript -Path $argsMatch.Groups['script'].Value -ExpectedPath $expected `
        -Marker 'Omada syslog viz - local web UI'
}

function Test-VizDesktopShortcutOwned($Shortcut) {
    if (-not $Shortcut) { return $false }
    if ([IO.Path]::GetFileName([string]$Shortcut.TargetPath) -notin @('powershell.exe', 'pwsh.exe')) { return $false }
    if ([string]$Shortcut.Description -ne 'Omada Logger & Viz - live traffic dashboard') { return $false }
    $argsMatch = [regex]::Match([string]$Shortcut.Arguments,
        '(?i)^\s*-NoProfile\s+-ExecutionPolicy\s+Bypass\s+-File\s+"(?<script>[^"\r\n]+[\\/]viz\.ps1)"\s*$')
    if (-not $argsMatch.Success) { return $false }
    $expected = Join-Path $script:InstallerRoot 'viz.ps1'
    return Test-RecognizedProductScript -Path $argsMatch.Groups['script'].Value -ExpectedPath $expected `
        -Marker 'Omada Viz launcher - one click to the live traffic dashboard'
}

function Test-InstallerResourceConflicts([string]$StartupShortcut, [string]$DesktopShortcut) {
    $task = Get-VizBootTask
    if ($task -and -not (Test-VizBootTaskOwned $task)) {
        throw "Task 'Omada Viz Server' already exists but its single action cannot be verified as this Omada Viz product. Leave it unchanged or remove it yourself, then retry."
    }
    $startup = Get-VizStartupShortcut $StartupShortcut
    if ($startup -and -not (Test-VizStartupShortcutOwned $startup)) {
        throw "Startup shortcut '$StartupShortcut' already exists but cannot be verified as this Omada Viz product. Leave it unchanged or move it yourself, then retry."
    }
    $desktop = Get-VizDesktopShortcut $DesktopShortcut
    if ($desktop -and -not (Test-VizDesktopShortcutOwned $desktop)) {
        throw "Desktop shortcut '$DesktopShortcut' already exists but cannot be verified as this Omada Viz product. Leave it unchanged or move it yourself, then retry."
    }
}

function New-VizDesktopShortcut {
    param([string]$DesktopShortcut, [string]$VizScript, [string]$Python, [string]$WorkingDirectory)
    $existing = Get-VizDesktopShortcut $DesktopShortcut
    if ($existing -and -not (Test-VizDesktopShortcutOwned $existing)) {
        throw "Desktop shortcut '$DesktopShortcut' is not a verifiable Omada Viz shortcut; leaving it untouched."
    }
    $ws = New-Object -ComObject WScript.Shell
    $shortcut = $ws.CreateShortcut($DesktopShortcut)
    $shortcut.TargetPath = 'powershell.exe'
    $shortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $VizScript + '"'
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.Description = 'Omada Logger & Viz - live traffic dashboard'
    if ($Python) { $shortcut.IconLocation = "$Python,0" }
    $shortcut.Save()
    $installed = Get-VizDesktopShortcut $DesktopShortcut
    if (-not (Test-VizDesktopShortcutOwned $installed)) {
        throw "The Omada Viz desktop shortcut could not be verified at '$DesktopShortcut'."
    }
}

function New-VizStartupShortcut {
    param([string]$StartupShortcut, [string]$Python, [string]$VizScript, [string]$WorkingDirectory)
    $existing = Get-VizStartupShortcut $StartupShortcut
    if ($existing -and -not (Test-VizStartupShortcutOwned $existing)) {
        throw "Startup shortcut '$StartupShortcut' is not a verifiable Omada Viz shortcut; leaving it untouched."
    }
    $ws = New-Object -ComObject WScript.Shell
    $shortcut = $ws.CreateShortcut($StartupShortcut)
    $shortcut.TargetPath = $Python
    $shortcut.Arguments = '"' + $VizScript + '" --port 8780'
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.WindowStyle = 7
    $shortcut.Description = 'Omada Logger & Viz - auto-start the traffic dashboard'
    $shortcut.Save()
}

function Register-VizBootTask {
    param([string]$Python, [string]$VizScript, [string]$WorkingDirectory)
    $existingTask = Get-VizBootTask
    if ($existingTask -and -not (Test-VizBootTaskOwned $existingTask)) {
        throw "Task 'Omada Viz Server' is not a verifiable Omada Viz task; leaving it untouched. Check its single action, target script, and description before retrying."
    }
    $vizAction = New-ScheduledTaskAction -Execute $Python `
        -Argument ('"' + $VizScript + '" --port 8780') `
        -WorkingDirectory $WorkingDirectory
    $vizBootTrig = New-ScheduledTaskTrigger -AtStartup
    $vizLogonTrig = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    $vizTrigger = @($vizBootTrig, $vizLogonTrig)
    $vizPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Limited
    $vizSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName 'Omada Viz Server' -Action $vizAction -Trigger $vizTrigger `
        -Principal $vizPrincipal -Settings $vizSettings -Force `
        -Description 'Always-on localhost web UI for Omada Logger & Viz (http://localhost:8780)' | Out-Null
    Start-ScheduledTask -TaskName 'Omada Viz Server'
    $installedTask = Get-VizBootTask
    if (-not (Test-VizBootTaskOwned $installedTask)) {
        throw "Task Scheduler did not verify the Omada Viz Server action after registration."
    }
}

function Set-VizStartupMode {
    param(
        [switch]$VizBoot,
        [string]$Python,
        [string]$VizScript,
        [string]$StartupShortcut,
        [string]$WorkingDirectory
    )

    $priorTask = Get-VizBootTask
    $priorShortcut = Get-VizStartupShortcut $StartupShortcut
    if ($priorTask -and -not (Test-VizBootTaskOwned $priorTask)) {
        throw "Task 'Omada Viz Server' is not a verifiable Omada Viz task; leaving it untouched. Check its single action, target script, and description before retrying."
    }
    if ($priorShortcut -and -not (Test-VizStartupShortcutOwned $priorShortcut)) {
        throw "Startup shortcut '$StartupShortcut' exists but does not match the Omada Viz launcher; leaving it untouched."
    }

    if ($VizBoot) {
        $taskWasPresent = [bool]$priorTask
        try {
            Register-VizBootTask -Python $Python -VizScript $VizScript -WorkingDirectory $WorkingDirectory
            if ($priorShortcut) { Remove-VizStartupShortcut $StartupShortcut }
        }
        catch {
            if (-not $taskWasPresent) {
                try { Remove-VizBootTask } catch { }
            }
            throw "Could not switch Omada Viz startup to the boot task; prior startup remains available. $($_.Exception.Message)"
        }
    }
    else {
        if (-not $Python) {
            if ($priorTask) { Remove-VizBootTask }
            if ($priorShortcut) { Remove-VizStartupShortcut $StartupShortcut }
            return
        }
        $shortcutWasPresent = [bool]$priorShortcut
        try {
            New-VizStartupShortcut -StartupShortcut $StartupShortcut -Python $Python `
                -VizScript $VizScript -WorkingDirectory $WorkingDirectory
            $installedShortcut = Get-VizStartupShortcut $StartupShortcut
            if (-not (Test-VizStartupShortcutOwned $installedShortcut)) {
                throw "The Omada Viz startup shortcut could not be verified at '$StartupShortcut'."
            }
            if ($priorTask) { Remove-VizBootTask }
        }
        catch {
            if (-not $shortcutWasPresent) {
                try { Remove-VizStartupShortcut $StartupShortcut } catch { }
            }
            throw "Could not switch Omada Viz startup to a logon shortcut; prior startup remains available. $($_.Exception.Message)"
        }
    }
}

function Test-InstallerPayload([string]$Root) {
    $requiredFiles = @(
        'omada_syslog.py',
        'omada_event_store.py',
        'omada_condenser.py',
        'watchdog.ps1',
        'watchdog-health.ps1',
        'omada_viz.py',
        'viz.html',
        'viz.ps1'
    )
    $missing = @($requiredFiles | Where-Object { -not (Test-Path -LiteralPath (Join-Path $Root $_) -PathType Leaf) })
    if ($missing.Count) {
        $list = ($missing | ForEach-Object { "  - $_" }) -join [Environment]::NewLine
        throw "Installer payload is incomplete. Missing required runtime files:`n$list`nRestore these files beside install.ps1, then run the installer again. No system changes were made."
    }
}

# Validate the complete runtime bundle before prompting for elevation or
# creating any Windows resources.
Test-InstallerPayload -Root $PSScriptRoot

# --- self-elevate ------------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $argList = Get-ElevatedRelaunchArguments -ScriptPath $PSCommandPath -TaskArgs $TaskArgs -VizBoot:$VizBoot
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
$vizScript = Join-Path $PSScriptRoot 'omada_viz.py'
$startupShortcut = Join-Path ([Environment]::GetFolderPath('Startup')) 'Omada Viz.lnk'
$desktopShortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Omada Viz.lnk'
# Check all same-named resources before creating the data directory, firewall
# rule, or receiver/watchdog tasks. An unreadable resource is a conflict too.
Test-InstallerResourceConflicts -StartupShortcut $startupShortcut -DesktopShortcut $desktopShortcut

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
# This installer now deploys a heartbeat-aware receiver/watchdog. Arm it here
# so a startup bind failure is detected; older installs without this marker
# remain observation-only until they are explicitly upgraded.
Set-Content -LiteralPath (Join-Path $LogDir '.receiver-heartbeat-armed') `
    -Value (Get-Date -Format o)

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
    # The watchdog only controls this user's tasks/processes and writes under
    # LOCALAPPDATA; keep it unelevated because its script lives beside the app.
    $wdPrincipal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Limited
    $wdSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName 'Omada Syslog Watchdog' -Action $wdAction -Trigger $wdTrigger `
        -Principal $wdPrincipal -Settings $wdSettings -Force `
        -Description 'Keeps the receiver (heartbeat health) and viz (HTTP health) alive' | Out-Null
    Write-Host "Watchdog registered (every 5 min: receiver heartbeat restart + viz HTTP health heal)"
}

# --- desktop shortcut: one double-click to the viz ----------------------------
New-VizDesktopShortcut -DesktopShortcut $desktopShortcut -VizScript (Join-Path $PSScriptRoot 'viz.ps1') `
    -Python $pyw -WorkingDirectory $PSScriptRoot
Write-Host "Desktop shortcut created: $desktopShortcut"

# --- reconcile the mutually exclusive viz auto-start mechanisms --------------
if (Test-Path -LiteralPath $vizScript) {
    Set-VizStartupMode -VizBoot:$VizBoot -Python $pyw -VizScript $vizScript `
        -StartupShortcut $startupShortcut -WorkingDirectory $PSScriptRoot
    if ($VizBoot) {
        Write-Host 'Viz boot task registered + started (always available at http://localhost:8780)'
    }
    elseif ($pyw) {
        Write-Host "Startup shortcut created: $startupShortcut"
    }
}

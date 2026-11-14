<#
Omada Syslog Receiver - uninstaller.

Removes only resources whose task action/description, shortcut target, or
firewall configuration identifies them as this product. Log data in
%LOCALAPPDATA%\OmadaSyslog is kept by default; -PurgeLogs opts in to deletion.
#>
param([switch]$PurgeLogs)

$ErrorActionPreference = 'Stop'
$script:InstallerRoot = $PSScriptRoot
$script:TaskSpecs = @(
    @{ Name = 'Omada Syslog Receiver'; Kind = 'Receiver' },
    @{ Name = 'Omada Syslog Watchdog'; Kind = 'Watchdog' },
    @{ Name = 'Omada Viz Server'; Kind = 'Viz' }
)
$script:RuleName = 'Omada Syslog UDP 514 inbound'

function Test-ProductScript([string]$Path, [string]$ExpectedPath, [string]$Marker) {
    try { $full = [IO.Path]::GetFullPath($Path) } catch { return $false }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return $false }
    try { $content = Get-Content -LiteralPath $full -Raw -ErrorAction Stop }
    catch { throw "Could not inspect product script '$full'; no uninstall changes were made. $($_.Exception.Message)" }
    # The stable source marker also recognizes a moved checkout while its
    # original script remains readable. Never infer ownership from a path alone.
    return $content.Contains($Marker)
}

function Test-ProductTask($Task, [string]$Kind) {
    if (-not $Task -or @($Task.Actions).Count -ne 1) { return $false }
    $action = @($Task.Actions)[0]
    $exe = [IO.Path]::GetFileName([string]$action.Execute)
    $arguments = [string]$action.Arguments
    switch ($Kind) {
        'Receiver' {
            if ([string]$Task.Description -ne 'UDP/514 syslog receiver for TP-Link Omada ER8411 remote logging (per-user)' -or
                $exe -notin @('python.exe', 'pythonw.exe')) { return $false }
            $m = [regex]::Match($arguments, '(?i)^\s*"(?<script>[^"\r\n]+[\\/]omada_syslog\.py)"\s+--log-file\s+"[^"\r\n]+"(?:\s+.*)?$')
            return ($m.Success -and (Test-ProductScript $m.Groups['script'].Value (Join-Path $script:InstallerRoot 'omada_syslog.py') 'Omada syslog receiver'))
        }
        'Watchdog' {
            if ([string]$Task.Description -notin @(
                'Restarts the receiver task if the raw log goes stale (hung process / post-sleep)',
                'Keeps the receiver (stale log) and viz (HTTP health) alive',
                'Keeps the receiver (heartbeat health) and viz (HTTP health) alive'
            ) -or
                $exe -notin @('powershell.exe', 'pwsh.exe')) { return $false }
            $m = [regex]::Match($arguments, '(?i)^\s*-NoProfile\s+-ExecutionPolicy\s+Bypass\s+-WindowStyle\s+Hidden\s+-File\s+"(?<script>[^"\r\n]+[\\/]watchdog\.ps1)"\s*$')
            return ($m.Success -and (Test-ProductScript $m.Groups['script'].Value (Join-Path $script:InstallerRoot 'watchdog.ps1') 'Omada Syslog Watchdog - keeps the receiver'))
        }
        'Viz' {
            if ($Task.Description -and [string]$Task.Description -notmatch 'Omada Logger & Viz') { return $false }
            if ($exe -notin @('python.exe', 'pythonw.exe')) { return $false }
            $m = [regex]::Match($arguments, '(?i)^\s*"(?<script>[^"\r\n]+[\\/]omada_viz\.py)"\s+--port\s+8780\s*$')
            return ($m.Success -and (Test-ProductScript $m.Groups['script'].Value (Join-Path $script:InstallerRoot 'omada_viz.py') 'Omada syslog viz - local web UI'))
        }
    }
    return $false
}

function Get-ProductTask([string]$Name) {
    try { Get-ScheduledTask -TaskName $Name -ErrorAction Stop }
    catch {
        if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound) { return $null }
        throw "Could not inspect scheduled task '$Name'; no uninstall changes were made. $($_.Exception.Message)"
    }
}

function Get-ShortcutInfo([string]$Path) {
    try { Get-Item -LiteralPath $Path -ErrorAction Stop | Out-Null }
    catch [System.Management.Automation.ItemNotFoundException] { return $null }
    catch [System.IO.FileNotFoundException] { return $null }
    catch [System.IO.DirectoryNotFoundException] { return $null }
    catch { throw "Could not inspect shortcut '$Path'; no uninstall changes were made. $($_.Exception.Message)" }
    try {
        $ws = New-Object -ComObject WScript.Shell
        $ws.CreateShortcut($Path)
    } catch { throw "Could not read shortcut '$Path'; no uninstall changes were made. $($_.Exception.Message)" }
}

function Test-ProductShortcut($Shortcut, [string]$Kind) {
    if (-not $Shortcut) { return $false }
    switch ($Kind) {
        'Desktop' {
            if ([IO.Path]::GetFileName([string]$Shortcut.TargetPath) -notin @('powershell.exe', 'pwsh.exe') -or
                [string]$Shortcut.Description -ne 'Omada Logger & Viz - live traffic dashboard') { return $false }
            $m = [regex]::Match([string]$Shortcut.Arguments, '(?i)^\s*-NoProfile\s+-ExecutionPolicy\s+Bypass\s+-File\s+"(?<script>[^"\r\n]+[\\/]viz\.ps1)"\s*$')
            return ($m.Success -and (Test-ProductScript $m.Groups['script'].Value (Join-Path $script:InstallerRoot 'viz.ps1') 'Omada Viz launcher - one click to the live traffic dashboard'))
        }
        'Startup' {
            if ([IO.Path]::GetFileName([string]$Shortcut.TargetPath) -notin @('python.exe', 'pythonw.exe')) { return $false }
            if ($Shortcut.Description -and [string]$Shortcut.Description -ne 'Omada Logger & Viz - auto-start the traffic dashboard') { return $false }
            $m = [regex]::Match([string]$Shortcut.Arguments, '(?i)^\s*"(?<script>[^"\r\n]+[\\/]omada_viz\.py)"\s+--port\s+8780\s*$')
            return ($m.Success -and (Test-ProductScript $m.Groups['script'].Value (Join-Path $script:InstallerRoot 'omada_viz.py') 'Omada syslog viz - local web UI'))
        }
    }
    return $false
}

function Test-ProductFirewallRule($Rule) {
    if (-not $Rule -or $Rule.Direction -ne 'Inbound' -or $Rule.Action -ne 'Allow') { return $false }
    try {
        $port = $Rule | Get-NetFirewallPortFilter -ErrorAction Stop
        $address = $Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
    } catch { throw "Could not inspect firewall rule '$script:RuleName'; no uninstall changes were made. $($_.Exception.Message)" }
    return ([string]$port.Protocol -eq 'UDP' -and [string]$port.LocalPort -eq '514' -and
        (@($address.RemoteAddress) -join ',') -eq '192.168.0.0/24' -and
        (@($Rule.Profile) -join ',') -in @('Private, Domain', 'Domain, Private', 'Private,Domain', 'Domain,Private'))
}

function Test-NoReparsePoints([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root)) { return }
    $rootInfo = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    if (($rootInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Log purge path '$Root' is a reparse point; refusing deletion before uninstall changes."
    }
    if (-not $rootInfo.PSIsContainer) { throw "Log purge path '$Root' is not a directory; refusing deletion before uninstall changes." }

    # Walk one directory at a time and never enumerate a directory until it has
    # been checked. This detects nested junctions/symlinks without traversing
    # their targets.
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($Root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        try { $children = Get-PurgeDirectoryChildren $directory }
        catch { throw "Could not inspect log folder '$directory'; refusing purge before uninstall changes. $($_.Exception.Message)" }
        foreach ($child in $children) {
            try { $item = Get-Item -LiteralPath $child -Force -ErrorAction Stop }
            catch { throw "Could not inspect log item '$child'; refusing purge before uninstall changes. $($_.Exception.Message)" }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Log item '$child' is a reparse point; refusing deletion before uninstall changes."
            }
            if ($item.PSIsContainer) { $pending.Enqueue($child) }
        }
    }
}

function Get-PurgeDirectoryChildren([string]$Directory) {
    [IO.Directory]::GetFileSystemEntries($Directory)
}

function Get-ProductFirewallRules {
    try { @(Get-NetFirewallRule -DisplayName $script:RuleName -ErrorAction Stop) }
    catch {
        if ($_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound) { return @() }
        throw "Could not inspect firewall rule '$script:RuleName'; no uninstall changes were made. $($_.Exception.Message)"
    }
}

function Get-UninstallPlan {
    $plan = [ordered]@{ Tasks = @(); Shortcuts = @(); FirewallRules = @() }
    foreach ($spec in $script:TaskSpecs) {
        $task = Get-ProductTask $spec.Name
        if (-not $task) { continue }
        if (-not (Test-ProductTask $task $spec.Kind)) {
            throw "Task '$($spec.Name)' exists but its ownership cannot be verified. It was left untouched; inspect its action and target script, then remove it manually if appropriate. No uninstall changes were made."
        }
        $plan.Tasks += [pscustomobject]@{ Name = $spec.Name; State = $task.State }
    }
    $desktop = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Omada Viz.lnk'
    $startup = Join-Path ([Environment]::GetFolderPath('Startup')) 'Omada Viz.lnk'
    foreach ($item in @(@{ Path = $desktop; Kind = 'Desktop' }, @{ Path = $startup; Kind = 'Startup' })) {
        $shortcut = Get-ShortcutInfo $item.Path
        if (-not $shortcut) { continue }
        if (-not (Test-ProductShortcut $shortcut $item.Kind)) {
            throw "Shortcut '$($item.Path)' exists but its ownership cannot be verified. It was left untouched; inspect its target and description, then remove it manually if appropriate. No uninstall changes were made."
        }
        $plan.Shortcuts += $item.Path
    }
    $rules = Get-ProductFirewallRules
    foreach ($rule in $rules) {
        if (-not (Test-ProductFirewallRule $rule)) {
            throw "Firewall rule '$script:RuleName' exists but its ownership cannot be verified from the installer's UDP 514/LAN configuration. It was left untouched; inspect and remove it manually if appropriate. No uninstall changes were made."
        }
        $plan.FirewallRules += $rule
    }
    return $plan
}

function Invoke-ProductUninstall($Plan, [switch]$PurgeLogs) {
    $logRoot = $null
    if ($PurgeLogs) {
        $logRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'OmadaSyslog'))
        $localRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $logRoot.StartsWith($localRoot, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($logRoot) -ne 'OmadaSyslog') { throw "Log purge path '$logRoot' is outside the expected OmadaSyslog folder; refusing deletion before uninstall changes." }
        Test-NoReparsePoints $logRoot
    }
    $completed = [Collections.Generic.List[string]]::new()
    $operation = 'initializing uninstall'
    try {
        foreach ($task in $Plan.Tasks) {
            if ($task.State -eq 'Running') {
                $operation = "stopping task '$($task.Name)'"
                Stop-ScheduledTask -TaskName $task.Name -ErrorAction Stop
                $completed.Add($operation)
            }
        }
        foreach ($task in $Plan.Tasks) {
            $operation = "unregistering task '$($task.Name)'"
            Unregister-ScheduledTask -TaskName $task.Name -Confirm:$false -ErrorAction Stop
            $completed.Add($operation)
        }
        foreach ($path in $Plan.Shortcuts) {
            $operation = "removing shortcut '$path'"
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $path) { throw "Shortcut still exists after removal attempt." }
            $completed.Add($operation)
        }
        foreach ($rule in $Plan.FirewallRules) {
            $operation = "removing firewall rule '$script:RuleName'"
            $rule | Remove-NetFirewallRule -ErrorAction Stop
            $completed.Add($operation)
        }
        if ($PurgeLogs -and (Test-Path -LiteralPath $logRoot)) {
            $operation = "purging log folder '$logRoot'"
            # Revalidate immediately before recursive removal so a junction
            # created after the initial fail-before-mutation preflight is caught.
            Test-NoReparsePoints $logRoot
            Remove-Item -LiteralPath $logRoot -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $logRoot) { throw "Log folder still exists after purge attempt." }
            $completed.Add($operation)
        }
    } catch {
        $done = if ($completed.Count) { $completed -join '; ' } else { 'none' }
        throw "Uninstall stopped while $operation. Completed operations: $done. Failure: $($_.Exception.Message) No rollback was attempted; completed removals are irreversible. Resolve the reported issue, then rerun uninstall; it will inspect remaining resources again."
    }
}

function Invoke-UninstallerEntry {
    param([Parameter(Mandatory)][bool]$IsAdmin, [switch]$PurgeLogs)
    if ($IsAdmin -and $PurgeLogs) {
        throw 'For safety, -PurgeLogs must run from an unelevated PowerShell. The elevated process cannot purge logs; close it and rerun uninstall.ps1 -PurgeLogs from a normal PowerShell window.'
    }
    if (-not $IsAdmin) {
        if ($PurgeLogs) {
            # Read-only preflight keeps collisions/access failures from deleting
            # user data before the elevated uninstall has a chance to refuse.
            $null = Get-UninstallPlan
            Write-Warning 'The log folder will be purged now, before the UAC prompt. If you cancel UAC afterward, the logs are already deleted and cannot be restored.'
            # This process is still using the original, unelevated user token.
            Invoke-ProductUninstall -Plan ([pscustomobject]@{ Tasks = @(); Shortcuts = @(); FirewallRules = @() }) -PurgeLogs
        }
        $launchArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
        try {
            $childProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList $launchArgs -Verb RunAs -Wait -PassThru -ErrorAction Stop
        } catch {
            if ($PurgeLogs) {
                throw "The log purge already completed, but the elevated uninstall did not start or was canceled. The remaining Windows resources were not removed. Run uninstall.ps1 again without -PurgeLogs after resolving the UAC issue. $($_.Exception.Message)"
            }
            throw "The elevated uninstall did not start or was canceled; no Windows resources were removed. $($_.Exception.Message)"
        }
        if (-not $childProcess) {
            if ($PurgeLogs) { throw 'The log purge already completed, but the elevated uninstall returned no process status. Windows resource removal could not be confirmed; inspect the elevated process output and rerun without -PurgeLogs if needed.' }
            throw 'The elevated uninstall returned no process status, so Windows resource removal could not be confirmed. Inspect the elevated process output and rerun if needed.'
        }
        if ($null -ne $childProcess.ExitCode -and [int]$childProcess.ExitCode -ne 0) {
            $exitCode = [int]$childProcess.ExitCode
            if ($PurgeLogs) {
                throw "The log purge already completed, but the elevated uninstall exited with code $exitCode. Windows resources may be partially removed; inspect the elevated process output, then rerun uninstall.ps1 without -PurgeLogs."
            }
            throw "The elevated uninstall exited with code $exitCode. Windows resources may be partially removed; inspect the elevated process output, then rerun uninstall.ps1 after resolving the reported issue."
        }
        return
    }
    $plan = Get-UninstallPlan
    Invoke-ProductUninstall -Plan $plan
    Write-Host 'Removed verified Omada tasks, shortcuts, and firewall rule.'
    Write-Host 'Log data left untouched at %LOCALAPPDATA%\OmadaSyslog.'
}

if ($MyInvocation.InvocationName -ne '.') {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Invoke-UninstallerEntry -IsAdmin:$isAdmin -PurgeLogs:$PurgeLogs
}

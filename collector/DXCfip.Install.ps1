<#
DXCfip.Install.ps1 v1.2.0 - shared install/uninstall logic for the DX CF-IP collector.
Dot-sourced (never run directly) by:
  * install.ps1                          - the irm|iex one-liner (downloads this file + the collector)
  * collector/Install-DXCfipCollector.ps1 - the N-central installer (file next to it, or embedded in the bundle)
Functions return exit codes; they never call exit. No secrets in this file.

OS-specific actions go through $DXCfipOps (scriptblocks). The test suite swaps them for fakes by setting
$global:DXCfipOpsOverride before loading; nothing in production sets it.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'Test seam: $global:DXCfipOpsOverride')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Console output for N-central / technician')]
param()

$DXCfipTaskPath = '\DX\'
$DXCfipTaskName = 'DX-CFIP-Collector'
$DXCfipMarker = 'DX Cloudflare trusted-IP collector'
# Files this tool creates, relative to the root. Migration and uninstall only ever delete these.
$DXCfipKnownFiles = [ordered]@{
    Scripts = @('Invoke-DXCfipCollector.ps1')
    Config  = @('cfip-collector.json')
    State   = @('cfip-collector-state.json')
    Logs    = @('DX-CFIP-Collector.log', 'DX-CFIP-Collector.log.1')
}
$DXCfipNetFxKeys = @('HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')
$DXCfipNetFxValues = @('SchUseStrongCrypto', 'SystemDefaultTlsVersions')

$DXCfipOps = @{
    IsWindows      = { $env:OS -eq 'Windows_NT' }
    IsElevated     = {
        $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    CanPrompt      = {
        $id = $null
        if ($env:OS -eq 'Windows_NT') { $id = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
        [Environment]::UserInteractive -and $id -ne 'S-1-5-18' -and
        -not ([Environment]::GetCommandLineArgs() -match '^-(noni|noninteractive)$')
    }
    ReadToken      = { Read-Host -Prompt 'DX CF-IP report token for this client (input hidden)' -AsSecureString }
    Is64BitOS      = { [Environment]::Is64BitOperatingSystem }
    ProtectPath    = {
        param([string]$Path, [bool]$Directory)
        # SYSTEM (S-1-5-18) + BUILTIN\Administrators (S-1-5-32-544) full control, inheritance from the parent removed
        # (C:\Windows would otherwise hand down Users read, TrustedInstaller, CREATOR OWNER). SIDs, not names, so it
        # works on non-English Windows.
        $acl = Get-Acl -LiteralPath $Path
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($r in @($acl.Access)) { [void]$acl.RemoveAccessRule($r) }
        $inherit = [System.Security.AccessControl.InheritanceFlags]::None
        if ($Directory) { $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' }
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', $inherit,
                            [System.Security.AccessControl.PropagationFlags]::None, 'Allow')))
        }
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    RegisterTask   = {
        param([string]$Arguments)
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $action = New-ScheduledTaskAction -Execute $psExe -Argument $Arguments
        $hourly = New-ScheduledTaskTrigger -Once -At (Get-Date).Date.AddHours((Get-Date).Hour + 1) `
            -RepetitionInterval (New-TimeSpan -Hours 1) -RandomDelay (New-TimeSpan -Minutes 10)
        $boot = New-ScheduledTaskTrigger -AtStartup
        $boot.Delay = 'PT5M'
        $principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskPath $DXCfipTaskPath -TaskName $DXCfipTaskName -Action $action -Trigger @($hourly, $boot) `
            -Principal $principal -Settings $settings -Force `
            -Description 'DX: report this site''s public IP to the DX CF-IP service (Cloudflare trusted IPs)' | Out-Null
    }
    GetTaskArguments = {
        # Arguments of the existing task's action, '' if there is no task (or no ScheduledTasks module).
        try {
            $t = Get-ScheduledTask -TaskPath $DXCfipTaskPath -TaskName $DXCfipTaskName -ErrorAction Stop
            return (@($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ')
        }
        catch { return '' }
    }
    GetRegDword    = {
        param([string]$Path, [string]$Name)
        try { return [int]((Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name) } catch { return $null }
    }
    SetRegDword    = {
        param([string]$Path, [string]$Name, [int]$Value)
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
    }
    UnregisterTask = {
        if (Get-ScheduledTask -TaskPath $DXCfipTaskPath -TaskName $DXCfipTaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskPath $DXCfipTaskPath -TaskName $DXCfipTaskName -Confirm:$false
            return $true
        }
        return $false
    }
    RunCollector   = {
        param([string]$Arguments)
        # Child Windows PowerShell 5.1, exactly as the task runs it. The token is read from the ACL'd
        # config file by the child, never passed on the command line.
        $psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $p = Start-Process -FilePath $psExe -ArgumentList "$Arguments -Force" -Wait -PassThru -NoNewWindow
        return $p.ExitCode
    }
}
if ($global:DXCfipOpsOverride -is [hashtable]) {
    foreach ($k in @($global:DXCfipOpsOverride.Keys)) { $DXCfipOps[$k] = $global:DXCfipOpsOverride[$k] }
}

function Write-DXInstallLog([string]$Msg, [string]$Level = 'INFO') {
    Write-Host ('{0} DX cfip-install {1,-5} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Msg)
}

function Enable-DXTlsProtocol {
    # TLS 1.2 always; TLS 1.3 only on Windows build 20348+ (forcing it on older builds breaks .NET Framework handshakes).
    try {
        $p = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $build = 0
        if ($env:OS -eq 'Windows_NT') { $build = [Environment]::OSVersion.Version.Build }
        if ($build -ge 20348 -and [enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
            $p = $p -bor [Net.SecurityProtocolType]::Tls13
        }
        [Net.ServicePointManager]::SecurityProtocol = $p
    }
    catch { $null = $_ }
}

function Get-DXCfipDefaultRoot {
    # C:\Windows\Scripts\DX (follows %SystemRoot% if Windows lives elsewhere).
    $sr = [string]$env:SystemRoot
    if (-not $sr) { $sr = 'C:\Windows' }
    return ($sr.TrimEnd('\', '/') + '\Scripts\DX')
}

function Get-DXCfipLegacyRoot {
    # Where versions before 1.2 installed: C:\DX
    $sd = [string]$env:SystemDrive
    if (-not $sd) { $sd = 'C:' }
    return ($sd.TrimEnd('\', '/') + '\DX')
}

function Resolve-DXCfipRoot([string]$Value) {
    # DX_CFIP_ROOTDIR / -RootDir override, else the default root.
    if ([string]::IsNullOrWhiteSpace($Value)) { return Get-DXCfipDefaultRoot }
    return $Value.Trim()
}

function Get-DXCfipPath([string]$RootDir) {
    $o = [ordered]@{ Root = $RootDir; Scripts = (Join-Path $RootDir 'Scripts'); Config = (Join-Path $RootDir 'Config')
        State = (Join-Path $RootDir 'State'); Logs = (Join-Path $RootDir 'Logs') }
    $o.Collector = Join-Path $o.Scripts 'Invoke-DXCfipCollector.ps1'
    $o.ConfigFile = Join-Path $o.Config 'cfip-collector.json'
    $o.StateFile = Join-Path $o.State 'cfip-collector-state.json'
    return [pscustomobject]$o
}

function ConvertTo-DXReportUrl([string]$Endpoint) {
    # Accepts https://host, https://host/ or https://host/report; returns the /report URL or '' if invalid.
    $e = ([string]$Endpoint).Trim()
    if ($e -notmatch '^https://[A-Za-z0-9.-]+(:\d+)?(/.*)?$') { return '' }
    if ($e -match '^https://[^/]+/?$') { return ($e.TrimEnd('/') + '/report') }
    return $e
}

function Test-DXCfipScriptText([string]$Text, [string]$Marker) {
    # The downloaded text must parse cleanly and carry the expected marker string.
    if ([string]::IsNullOrWhiteSpace($Text) -or -not $Text.Contains($Marker)) { return $false }
    $tokens = $null; $errors = $null
    [void][Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    return (@($errors).Count -eq 0)
}

function Test-DXCfipSameRoot([string]$A, [string]$B) {
    $n = { param($x) ([string]$x).Replace('/', '\').TrimEnd('\').ToUpperInvariant() }
    return ((& $n $A) -eq (& $n $B))
}

function Get-DXCfipExistingToken([string]$ClientCode, [string[]]$Roots) {
    # A token from an existing config (new root first, then the old root) for the SAME client code, or ''.
    $code = ([string]$ClientCode).Trim().ToUpperInvariant()
    foreach ($r in $Roots) {
        if (-not $r) { continue }
        $f = (Get-DXCfipPath $r).ConfigFile
        if (-not (Test-Path -LiteralPath $f)) { continue }
        try {
            $c = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
            if (([string]$c.ClientCode).ToUpperInvariant() -eq $code -and [string]$c.Token -match '^[A-Za-z0-9_-]{20,128}$') { return [string]$c.Token }
        }
        catch { $null = $_ }
    }
    return ''
}

function Test-DXCfipLegacyInstall([string]$RootDir, [string]$LegacyRootDir) {
    # An install at the old root: the task points there, or any of our files exist there.
    if (-not $LegacyRootDir -or (Test-DXCfipSameRoot $RootDir $LegacyRootDir)) { return $false }
    $taskArgs = [string](& $DXCfipOps.GetTaskArguments)
    $norm = $LegacyRootDir.Replace('/', '\').TrimEnd('\') + '\'
    if ($taskArgs -and $taskArgs.Replace('/', '\').ToUpperInvariant().Contains($norm.ToUpperInvariant())) {
        Write-DXInstallLog "migration: scheduled task points at the old root $LegacyRootDir"
        return $true
    }
    foreach ($sub in $DXCfipKnownFiles.Keys) {
        foreach ($name in $DXCfipKnownFiles[$sub]) {
            if (Test-Path -LiteralPath (Join-Path (Join-Path $LegacyRootDir $sub) $name)) {
                Write-DXInstallLog "migration: found $(Join-Path (Join-Path $LegacyRootDir $sub) $name)"
                return $true
            }
        }
    }
    return $false
}

function Copy-DXCfipLegacyData([string]$RootDir, [string]$LegacyRootDir) {
    # Copies config + state (newer file wins; a newer file already at the new root is never overwritten) and our
    # log files (old lines first, then any new ones) to the new root. Old files are deleted later, only after the
    # task points at the new root, so a failed install leaves the old one working.
    foreach ($sub in @('Config', 'State')) {
        foreach ($name in $DXCfipKnownFiles[$sub]) {
            $src = Join-Path (Join-Path $LegacyRootDir $sub) $name
            $dst = Join-Path (Join-Path $RootDir $sub) $name
            if (-not (Test-Path -LiteralPath $src)) { continue }
            if (-not (Test-Path -LiteralPath $dst)) {
                Copy-Item -LiteralPath $src -Destination $dst -Force
                Write-DXInstallLog "migration: copied $src -> $dst"
            }
            elseif ((Get-Item -LiteralPath $src).LastWriteTimeUtc -gt (Get-Item -LiteralPath $dst).LastWriteTimeUtc) {
                Copy-Item -LiteralPath $src -Destination $dst -Force
                Write-DXInstallLog "migration: $src is newer, replaced $dst"
            }
            else { Write-DXInstallLog "migration: kept the newer $dst (old copy not used)" }
        }
    }
    foreach ($name in $DXCfipKnownFiles['Logs']) {
        $src = Join-Path (Join-Path $LegacyRootDir 'Logs') $name
        $dst = Join-Path (Join-Path $RootDir 'Logs') $name
        if (-not (Test-Path -LiteralPath $src)) { continue }
        if (Test-Path -LiteralPath $dst) {
            $merged = [IO.File]::ReadAllText($src) + [IO.File]::ReadAllText($dst)
            [IO.File]::WriteAllText($dst, $merged)
            Write-DXInstallLog "migration: merged $src into $dst (old lines first)"
        }
        else {
            Copy-Item -LiteralPath $src -Destination $dst -Force
            Write-DXInstallLog "migration: copied $src -> $dst"
        }
    }
}

function Invoke-DXCfipCleanup([string]$Root, [string[]]$Subfolders) {
    # Deletes only our known files in the given subfolders, then each subfolder and the root if they are empty.
    # Anything else is left where it is and logged.
    foreach ($sub in $Subfolders) {
        foreach ($name in $DXCfipKnownFiles[$sub]) {
            $f = Join-Path (Join-Path $Root $sub) $name
            if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force; Write-DXInstallLog "removed $f" }
        }
    }
    foreach ($d in @(@($DXCfipKnownFiles.Keys | ForEach-Object { Join-Path $Root $_ }) + $Root)) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        $left = @(Get-ChildItem -LiteralPath $d -Force)
        if ($left.Count -eq 0) { Remove-Item -LiteralPath $d -Force; Write-DXInstallLog "removed empty folder $d" }
        elseif ($d -ne $Root) { Write-DXInstallLog "kept $d (still holds: $(@($left | ForEach-Object Name) -join ', '))" }
        else { Write-DXInstallLog "kept $d (not empty)" }
    }
}

function Invoke-DXCfipTlsCheck([switch]$Fix) {
    # .NET Framework strong-crypto / OS-default TLS. Without them some older Windows builds fail the TLS 1.2 handshake
    # ("Could not create SSL/TLS secure channel"). Machine-wide, so only changed with DX_CFIP_FIXTLS=1 / -FixTls.
    $keys = @($DXCfipNetFxKeys[0])
    if (& $DXCfipOps.Is64BitOS) { $keys += $DXCfipNetFxKeys[1] }
    $missing = @(); $changed = 0
    try {
        foreach ($k in $keys) {
            foreach ($n in $DXCfipNetFxValues) {
                $v = & $DXCfipOps.GetRegDword $k $n
                if ($v -eq 1) { continue }
                $was = 'missing'
                if ($null -ne $v) { $was = "was $v" }
                if ($Fix) {
                    & $DXCfipOps.SetRegDword $k $n 1
                    Write-DXInstallLog "TLS: set $k\$n = 1 (DWORD, $was)"
                    $changed++
                }
                else { $missing += "$k\$n ($was)" }
            }
        }
    }
    catch { Write-DXInstallLog "TLS: could not check/set .NET TLS registry values: $($_.Exception.Message)" 'WARN'; return }
    if ($changed) {
        Write-DXInstallLog "TLS: $changed machine-wide .NET value(s) changed. New processes (the scheduled task) use them; already-running apps need a restart, a reboot covers everything." 'WARN'
    }
    elseif ($missing.Count) {
        Write-DXInstallLog ("TLS: .NET strong crypto not fully enabled (" + ($missing -join '; ') +
            "). If reports fail with 'Could not create SSL/TLS secure channel', re-run with DX_CFIP_FIXTLS=1 (or -FixTls).") 'WARN'
    }
}

function Invoke-DXCfipInstall {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [string]$ClientCode, [string]$ReportUrl, [string]$Token, [int]$HeartbeatHours = 6,
        [string]$CollectorContent, [string]$RootDir = '', [string]$LegacyRootDir = '', [switch]$NoRunNow, [switch]$FixTls
    )
    $RootDir = Resolve-DXCfipRoot $RootDir
    if (-not $LegacyRootDir) { $LegacyRootDir = Get-DXCfipLegacyRoot }
    $ClientCode = ([string]$ClientCode).Trim().ToUpperInvariant()
    if ($ClientCode -notmatch '^[A-Z0-9][A-Z0-9_-]{1,31}$') { Write-DXInstallLog 'client code missing or invalid (2-32 chars: A-Z 0-9 _ -)' 'ERROR'; return 1 }
    if ($ReportUrl -notmatch '^https://[^\s/]+/') { Write-DXInstallLog 'report URL must be https://<host>/report' 'ERROR'; return 1 }
    if (-not $Token) {
        $Token = Get-DXCfipExistingToken $ClientCode @($RootDir, $LegacyRootDir)
        if ($Token) { Write-DXInstallLog "no token given: reusing the report token from the existing $ClientCode config" }
    }
    if ([string]$Token -notmatch '^[A-Za-z0-9_-]{20,128}$') { Write-DXInstallLog 'report token missing or malformed' 'ERROR'; return 1 }
    if ($HeartbeatHours -lt 1) { Write-DXInstallLog 'HeartbeatHours must be >= 1' 'ERROR'; return 1 }
    if (-not (Test-DXCfipScriptText $CollectorContent $DXCfipMarker)) { Write-DXInstallLog 'collector script missing or does not parse' 'ERROR'; return 3 }

    $p = Get-DXCfipPath $RootDir
    $taskArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$($p.Collector)`" -ConfigPath `"$($p.ConfigFile)`" " +
    "-StateDir `"$($p.State)`" -LogDir `"$($p.Logs)`""
    $legacy = $false
    try {
        $legacy = Test-DXCfipLegacyInstall $RootDir $LegacyRootDir
        if ($legacy) { Write-DXInstallLog "migration: existing install at $LegacyRootDir -> clean reinstall to $RootDir" }
        $parent = Split-Path -Parent $p.Root
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
            Write-DXInstallLog "created $parent"
        }
        foreach ($d in @($p.Root, $p.Scripts, $p.Config, $p.State, $p.Logs)) {
            if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
            & $DXCfipOps.ProtectPath $d $true
        }
        Write-DXInstallLog "folders under $($p.Root) (Scripts, Config, State, Logs): SYSTEM + Administrators only, not inherited"
        if ($legacy) { Copy-DXCfipLegacyData $RootDir $LegacyRootDir }
        Set-Content -LiteralPath $p.Collector -Value $CollectorContent -Encoding UTF8
        Write-DXInstallLog "collector -> $($p.Collector)"
        $cfg = [ordered]@{ ClientCode = $ClientCode; ReportUrl = $ReportUrl; Token = $Token; HeartbeatHours = $HeartbeatHours }
        Set-Content -LiteralPath $p.ConfigFile -Value ($cfg | ConvertTo-Json) -Encoding UTF8
        $cfg = $null
        & $DXCfipOps.ProtectPath $p.ConfigFile $false
        Write-DXInstallLog "config -> $($p.ConfigFile) (SYSTEM + Administrators only)"
        & $DXCfipOps.RegisterTask $taskArgs
        Write-DXInstallLog "task $DXCfipTaskPath$DXCfipTaskName registered (SYSTEM, hourly + at startup) -> $($p.Collector)"
        if ($legacy) {
            Write-DXInstallLog "migration: removing the old install's files from $LegacyRootDir"
            Invoke-DXCfipCleanup $LegacyRootDir @('Scripts', 'Config', 'State', 'Logs')
            Write-DXInstallLog 'migration: done'
        }
    }
    catch { Write-DXInstallLog "install failed: $($_.Exception.Message)" 'ERROR'; return 1 }
    Invoke-DXCfipTlsCheck -Fix:$FixTls

    if ($NoRunNow) { Write-DXInstallLog 'installed (first run skipped)'; return 0 }
    Write-DXInstallLog 'first collector run...'
    $rc = & $DXCfipOps.RunCollector $taskArgs
    if ($rc -ne 0) { Write-DXInstallLog "installed, but the first collector run returned $rc (see $($p.Logs)\DX-CFIP-Collector.log)" 'WARN'; return 4 }
    Write-DXInstallLog "installed and reported for $ClientCode"
    return 0
}

function Invoke-DXCfipUninstall {
    [CmdletBinding()]
    [OutputType([int])]
    param([string]$RootDir = '', [string]$LegacyRootDir = '')
    # Removes the task and our collector script, config (token) and state from the new AND the old (C:\DX) root,
    # then any of those folders left empty. Logs are kept (no secrets; the audit trail of what this machine reported).
    $RootDir = Resolve-DXCfipRoot $RootDir
    if (-not $LegacyRootDir) { $LegacyRootDir = Get-DXCfipLegacyRoot }
    $roots = @($RootDir)
    if (-not (Test-DXCfipSameRoot $RootDir $LegacyRootDir)) { $roots += $LegacyRootDir }
    try {
        if (& $DXCfipOps.UnregisterTask) { Write-DXInstallLog "removed task $DXCfipTaskPath$DXCfipTaskName" }
        foreach ($r in $roots) {
            if (Test-Path -LiteralPath $r) { Invoke-DXCfipCleanup $r @('Scripts', 'Config', 'State') }
        }
    }
    catch { Write-DXInstallLog "uninstall failed: $($_.Exception.Message)" 'ERROR'; return 1 }
    Write-DXInstallLog "uninstalled (logs kept in $($roots | ForEach-Object { Join-Path $_ 'Logs' } | Where-Object { Test-Path -LiteralPath $_ }))"
    return 0
}

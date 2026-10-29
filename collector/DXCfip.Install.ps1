<#
DXCfip.Install.ps1 v1.1.0 - shared install/uninstall logic for the DX CF-IP collector.
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
    ProtectPath    = {
        param([string]$Path, [bool]$Directory)
        # SYSTEM + BUILTIN\Administrators full control, inheritance from the parent removed.
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

function Invoke-DXCfipInstall {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [string]$ClientCode, [string]$ReportUrl, [string]$Token, [int]$HeartbeatHours = 6,
        [string]$CollectorContent, [string]$RootDir = 'C:\DX', [switch]$NoRunNow
    )
    $ClientCode = ([string]$ClientCode).Trim().ToUpperInvariant()
    if ($ClientCode -notmatch '^[A-Z0-9][A-Z0-9_-]{1,31}$') { Write-DXInstallLog 'client code missing or invalid (2-32 chars: A-Z 0-9 _ -)' 'ERROR'; return 1 }
    if ($ReportUrl -notmatch '^https://[^\s/]+/') { Write-DXInstallLog 'report URL must be https://<host>/report' 'ERROR'; return 1 }
    if ([string]$Token -notmatch '^[A-Za-z0-9_-]{20,128}$') { Write-DXInstallLog 'report token missing or malformed' 'ERROR'; return 1 }
    if ($HeartbeatHours -lt 1) { Write-DXInstallLog 'HeartbeatHours must be >= 1' 'ERROR'; return 1 }
    if (-not (Test-DXCfipScriptText $CollectorContent $DXCfipMarker)) { Write-DXInstallLog 'collector script missing or does not parse' 'ERROR'; return 3 }

    $p = Get-DXCfipPath $RootDir
    $taskArgs = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$($p.Collector)`" -ConfigPath `"$($p.ConfigFile)`" " +
    "-StateDir `"$($p.State)`" -LogDir `"$($p.Logs)`""
    try {
        foreach ($d in @($p.Root, $p.Scripts, $p.Config, $p.State, $p.Logs)) {
            if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        }
        & $DXCfipOps.ProtectPath $p.Config $true
        Set-Content -LiteralPath $p.Collector -Value $CollectorContent -Encoding UTF8
        Write-DXInstallLog "collector -> $($p.Collector)"
        $cfg = [ordered]@{ ClientCode = $ClientCode; ReportUrl = $ReportUrl; Token = $Token; HeartbeatHours = $HeartbeatHours }
        Set-Content -LiteralPath $p.ConfigFile -Value ($cfg | ConvertTo-Json) -Encoding UTF8
        $cfg = $null
        & $DXCfipOps.ProtectPath $p.ConfigFile $false
        Write-DXInstallLog "config -> $($p.ConfigFile) (SYSTEM + Administrators only)"
        & $DXCfipOps.RegisterTask $taskArgs
        Write-DXInstallLog "task $DXCfipTaskPath$DXCfipTaskName registered (SYSTEM, hourly + at startup)"
    }
    catch { Write-DXInstallLog "install failed: $($_.Exception.Message)" 'ERROR'; return 1 }

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
    param([string]$RootDir = 'C:\DX')
    # Removes the task, collector script, config (token) and state. Logs are kept: C:\DX\Logs is shared by other
    # DX tools, holds no secrets, and is the audit trail of what this machine reported.
    $p = Get-DXCfipPath $RootDir
    try {
        if (& $DXCfipOps.UnregisterTask) { Write-DXInstallLog "removed task $DXCfipTaskPath$DXCfipTaskName" }
        foreach ($f in @($p.Collector, $p.ConfigFile, $p.StateFile)) {
            if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force; Write-DXInstallLog "removed $f" }
        }
    }
    catch { Write-DXInstallLog "uninstall failed: $($_.Exception.Message)" 'ERROR'; return 1 }
    Write-DXInstallLog "uninstalled (logs kept in $($p.Logs))"
    return 0
}

<#
Install-DXCfipCollector.ps1 - N-central installer / uninstaller for the DX CF-IP collector.
(For the irm|iex one-liner use install.ps1 at the repo root; both share collector/DXCfip.Install.ps1.)

  * copies the collector to C:\DX\Scripts\Invoke-DXCfipCollector.ps1
  * writes C:\DX\Config\cfip-collector.json (client code, report URL, report token, heartbeat), ACL SYSTEM + Administrators
  * registers scheduled task \DX\DX-CFIP-Collector: SYSTEM, hourly (random delay up to 10 min) + at startup,
    Windows PowerShell 5.1, 10 min time limit, no overlapping runs
  * runs it once and reports the result

Shared code + collector (first found wins): copies embedded by tools/Build-Bundle.ps1 (single-file N-central script)
> DXCfip.Install.ps1 / Invoke-DXCfipCollector.ps1 next to this script. -CollectorSource overrides the collector.

N-central (run as LocalSystem):
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-DXCfipCollector.bundle.ps1 -ClientCode ACME `
      -ReportUrl https://cfip.example.com.au/report -Token <token from 'python -m cfip client add'>
  ... -Uninstall      removes the task, script, config and state (logs are kept)

Exit codes:
  0 = installed (first run OK) / uninstalled
  1 = error (bad parameters, copy/ACL/task registration failed, not Windows)
  2 = not elevated (needs Administrator or SYSTEM)
  3 = collector or shared install code not found / does not parse
  4 = installed, but the first collector run failed (see C:\DX\Logs\DX-CFIP-Collector.log; task stays registered)
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Used inside the & { } block')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Console output for N-central')]
[CmdletBinding()]
param(
    [string]$ClientCode = '',
    [string]$ReportUrl = '',
    [string]$Token = '',
    [int]$HeartbeatHours = 6,
    [string]$CollectorSource = '',
    [string]$RootDir = 'C:\DX',
    [switch]$Uninstall,
    [switch]$NoRunNow
)

$__DXScriptPath = $MyInvocation.MyCommand.Path
$__DXScriptRoot = $PSScriptRoot

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    # BEGIN-EMBEDDED (filled by tools/Build-Bundle.ps1; empty in the source tree)
    $EmbeddedLib = ''
    $EmbeddedCollector = ''
    # END-EMBEDDED

    function Exit-Install([int]$Code, [string]$Msg) {
        $lvl = 'INFO'
        if ($Code -ne 0) { $lvl = 'ERROR' }
        Write-Host ('{0} DX cfip-install {1,-5} {2} (exit {3})' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $lvl, $Msg, $Code)
        $global:LASTEXITCODE = $Code
        if ($__DXScriptPath -or -not [Environment]::UserInteractive -or
            ([Environment]::GetCommandLineArgs() -match '^-(c|command|noni|noninteractive|file|f|encodedcommand|e|ec)$')) {
            exit $Code
        }
    }

    function Read-Local([string]$Name) {
        if ($__DXScriptRoot) {
            $f = Join-Path $__DXScriptRoot $Name
            if (Test-Path -LiteralPath $f) { return (Get-Content -LiteralPath $f -Raw -Encoding UTF8) }
        }
        return ''
    }

    function Get-EnvOr([string]$Value, [string]$Name) {
        if ($Value) { return $Value }
        $e = [Environment]::GetEnvironmentVariable($Name)
        if ($e) { return $e.Trim() }
        return ''
    }

    $lib = $EmbeddedLib
    if (-not $lib) { $lib = Read-Local 'DXCfip.Install.ps1' }
    $tokens = $null; $errors = $null
    if (-not $lib -or -not $lib.Contains('function Invoke-DXCfipInstall')) { Exit-Install 3 'shared install code (DXCfip.Install.ps1) not found'; return }
    [void][Management.Automation.Language.Parser]::ParseInput($lib, [ref]$tokens, [ref]$errors)
    if (@($errors).Count) { Exit-Install 3 'shared install code does not parse'; return }
    . ([scriptblock]::Create($lib))

    if (-not (& $DXCfipOps.IsWindows)) { Exit-Install 1 'Windows only'; return }
    if (-not (& $DXCfipOps.IsElevated)) { Exit-Install 2 'run elevated (Administrator) or as SYSTEM'; return }

    if ($Uninstall) { $rc = Invoke-DXCfipUninstall -RootDir $RootDir; Exit-Install $rc 'uninstall finished'; return }

    $ClientCode = Get-EnvOr $ClientCode 'DX_CFIP_CLIENTCODE'
    $ReportUrl = ConvertTo-DXReportUrl (Get-EnvOr (Get-EnvOr $ReportUrl 'DX_CFIP_REPORTURL') 'DX_CFIP_ENDPOINT')
    $Token = Get-EnvOr $Token 'DX_CFIP_TOKEN'
    $CollectorSource = Get-EnvOr $CollectorSource 'DX_CFIP_COLLECTORURL'

    $content = ''
    try {
        if ($CollectorSource -match '^https://') {
            Enable-DXTlsProtocol
            $content = (Invoke-WebRequest -Uri $CollectorSource -UseBasicParsing -TimeoutSec 30).Content
        }
        elseif ($CollectorSource) { $content = Get-Content -LiteralPath $CollectorSource -Raw -Encoding UTF8 }
        elseif ($EmbeddedCollector) { $content = $EmbeddedCollector }
        else { $content = Read-Local 'Invoke-DXCfipCollector.ps1' }
    }
    catch { Exit-Install 3 "could not load collector: $($_.Exception.Message)"; return }

    $rc = Invoke-DXCfipInstall -ClientCode $ClientCode -ReportUrl $ReportUrl -Token $Token -HeartbeatHours $HeartbeatHours `
        -CollectorContent $content -RootDir $RootDir -NoRunNow:$NoRunNow
    $Token = $null
    Exit-Install $rc 'install finished'
}

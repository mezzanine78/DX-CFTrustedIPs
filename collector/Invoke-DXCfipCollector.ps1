<#
Invoke-DXCfipCollector.ps1 - DX Cloudflare trusted-IP collector (client side).

Runs hourly as SYSTEM (scheduled task \DX\DX-CFIP-Collector, registered by Install-DXCfipCollector.ps1)
on ONE machine per client site. Finds the site's public IPv4 and reports it, with the client code,
to the central DX CF-IP service behind NPM. No Cloudflare token is ever on the client: it holds only
a per-client report token that can do nothing except report this client's IP.

  1. Public IPv4 from https://api.ipify.org, falling back to https://ipv4.icanhazip.com and
     https://ifconfig.me/ip. Each answer must be a single, globally routable IPv4 address
     (private, CGNAT, loopback, link-local, documentation, multicast and reserved ranges are rejected).
  2. Reports only when the IP changed since the last successful report, or every -HeartbeatHours
     (default 6) as a heartbeat, or with -Force. If every provider fails it still reports (without an IP)
     so the server can use the source address it sees.

Windows PowerShell 5.1 and pwsh 7. irm|iex-safe (body in & { }, exit only when non-interactive).
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\DX\Scripts\Invoke-DXCfipCollector.ps1

Settings: parameter > environment variable > config file (C:\DX\Config\cfip-collector.json, ACL SYSTEM +
Administrators only, written by the installer). Env: DX_CFIP_CLIENTCODE, DX_CFIP_REPORTURL, DX_CFIP_TOKEN,
DX_CFIP_HEARTBEATHOURS. The token is never written to the log or the console.

Exit codes (N-central):
  0 = OK (reported, or nothing to report: IP unchanged and heartbeat not due)
  1 = configuration error (missing/invalid client code, report URL or token)
  2 = no public IPv4 could be determined (all providers failed and the server could not determine it)
  3 = report failed (network error, TLS, timeout, HTTP 5xx / 429)
  4 = report rejected: authentication (HTTP 401/403 - wrong/rotated token, client disabled, IP not allowed)
  5 = report rejected: other HTTP 4xx (bad request)
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Used inside the & { } block')]
[CmdletBinding()]
param(
    [string]$ClientCode = '',
    [string]$ReportUrl = '',          # e.g. https://cfip.example.com.au/report
    [string]$Token = '',              # prefer the config file / N-central secure property over this
    [string]$ConfigPath = '',         # default C:\DX\Config\cfip-collector.json
    [int]$HeartbeatHours = -1,        # default 6
    [string[]]$IpProviders = @(),     # default ipify, icanhazip, ifconfig.me
    [string]$StateDir = '',           # default C:\DX\State
    [string]$LogDir = '',             # default C:\DX\Logs
    [int]$TimeoutSec = 10,
    [switch]$Force,                   # report even if unchanged
    [switch]$DryRun,                  # detect and log the IP, do not report
    [switch]$AllowHttp                # allow http:// report URL (tests only)
)

$__DXScriptPath = $MyInvocation.MyCommand.Path

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    $ScriptVersion = '1.0.0'
    $DefaultProviders = @('https://api.ipify.org', 'https://ipv4.icanhazip.com', 'https://ifconfig.me/ip')
    $script:LogFile = $null

    function Write-DXLog([string]$Msg, [string]$Level = 'INFO') {
        $line = '{0} DX cfip-collector {1,-5} {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Msg
        Write-Host $line
        if ($script:LogFile) {
            try {
                if ((Test-Path -LiteralPath $script:LogFile) -and (Get-Item -LiteralPath $script:LogFile).Length -gt 1MB) {
                    Move-Item -LiteralPath $script:LogFile -Destination ($script:LogFile + '.1') -Force
                }
                Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
            }
            catch { $null = $_ }
        }
    }

    function Exit-Collector([int]$Code, [string]$Msg) {
        $lvl = 'INFO'
        if ($Code -ne 0) { $lvl = 'ERROR' }
        Write-DXLog "$Msg (exit $Code)" $lvl
        $global:LASTEXITCODE = $Code
        if ($__DXScriptPath -or -not [Environment]::UserInteractive -or
            ([Environment]::GetCommandLineArgs() -match '^-(c|command|noni|noninteractive|file|f|encodedcommand|e|ec)$')) {
            exit $Code
        }
    }

    function Test-DXPublicIPv4([string]$Value) {
        if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
        $v = $Value.Trim()
        if ($v -notmatch '^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$') { return $false }
        $o = [int[]]($v.Split('.'))
        $n = ([uint32]$o[0] -shl 24) -bor ([uint32]$o[1] -shl 16) -bor ([uint32]$o[2] -shl 8) -bor [uint32]$o[3]
        # Non-global IPv4 ranges (RFC 6890 / IANA special-purpose registry)
        $blocked = @(
            @('0.0.0.0', 8), @('10.0.0.0', 8), @('100.64.0.0', 10), @('127.0.0.0', 8), @('169.254.0.0', 16),
            @('172.16.0.0', 12), @('192.0.0.0', 24), @('192.0.2.0', 24), @('192.88.99.0', 24), @('192.168.0.0', 16),
            @('198.18.0.0', 15), @('198.51.100.0', 24), @('203.0.113.0', 24), @('224.0.0.0', 4), @('240.0.0.0', 4))
        foreach ($b in $blocked) {
            $bo = [int[]]($b[0].Split('.'))
            $bn = ([uint32]$bo[0] -shl 24) -bor ([uint32]$bo[1] -shl 16) -bor ([uint32]$bo[2] -shl 8) -bor [uint32]$bo[3]
            $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $b[1]))
            if (($n -band $mask) -eq $bn) { return $false }
        }
        return $true
    }

    function Enable-DXTlsProtocol {
        # TLS 1.2 always; TLS 1.3 only where the OS supports it (Windows build 20348+ / Win11).
        # Forcing Tls13 on older Windows breaks the handshake under .NET Framework.
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

    function Get-DXPublicIPv4([string[]]$Providers, [int]$Timeout) {
        foreach ($u in $Providers) {
            try {
                $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec $Timeout -Headers @{ 'User-Agent' = "dx-cfip-collector/$ScriptVersion" }
                $content = $r.Content
                if ($content -is [byte[]]) { $content = [Text.Encoding]::ASCII.GetString($content) }
                $ip = ([string]$content).Trim()
                if (Test-DXPublicIPv4 $ip) {
                    Write-DXLog "public IPv4 $ip from $u"
                    return [pscustomobject]@{ Ip = $ip; Provider = $u }
                }
                $shown = $ip
                if ($shown.Length -gt 40) { $shown = $shown.Substring(0, 40) + '...' }
                Write-DXLog "provider $u returned an invalid/non-public value '$shown', trying next" 'WARN'
            }
            catch {
                Write-DXLog "provider $u failed: $($_.Exception.Message), trying next" 'WARN'
            }
        }
        return $null
    }

    function Get-DXHttpStatus($ErrorRecord) {
        try {
            $resp = $ErrorRecord.Exception.Response
            if ($null -ne $resp -and $null -ne $resp.StatusCode) { return [int]$resp.StatusCode }
        }
        catch { $null = $_ }
        return 0
    }

    function Resolve-DXSetting($ParamValue, [string]$EnvName, $ConfigValue, $Default) {
        if ($null -ne $ParamValue -and "$ParamValue" -ne '' -and -not ($ParamValue -is [int] -and $ParamValue -lt 0)) { return $ParamValue }
        $e = [Environment]::GetEnvironmentVariable($EnvName)
        if (-not [string]::IsNullOrWhiteSpace($e)) { return $e.Trim() }
        if ($null -ne $ConfigValue -and "$ConfigValue" -ne '') { return $ConfigValue }
        return $Default
    }

    # ---------------------------------------------------------------- main
    $isWin = ($env:OS -eq 'Windows_NT')
    $root = 'C:\DX'
    if (-not $LogDir) { $LogDir = Join-Path $root 'Logs' }
    if (-not $StateDir) { $StateDir = Join-Path $root 'State' }
    if (-not $ConfigPath) { $ConfigPath = Join-Path $root 'Config\cfip-collector.json' }
    if (-not $isWin -and $LogDir -like 'C:\*') { $LogDir = $null }  # non-Windows test runs without -LogDir
    if ($LogDir) {
        try {
            if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
            $script:LogFile = Join-Path $LogDir 'DX-CFIP-Collector.log'
        }
        catch { $script:LogFile = $null }
    }
    Write-DXLog "start v$ScriptVersion on $([Environment]::MachineName) (PS $($PSVersionTable.PSVersion))"

    $cfg = $null
    if (Test-Path -LiteralPath $ConfigPath) {
        try { $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json }
        catch { Exit-Collector 1 "config file $ConfigPath is not valid JSON"; return }
    }
    $code = [string](Resolve-DXSetting -ParamValue $ClientCode -EnvName 'DX_CFIP_CLIENTCODE' -ConfigValue $cfg.ClientCode -Default '')
    $url = [string](Resolve-DXSetting -ParamValue $ReportUrl -EnvName 'DX_CFIP_REPORTURL' -ConfigValue $cfg.ReportUrl -Default '')
    $tok = [string](Resolve-DXSetting -ParamValue $Token -EnvName 'DX_CFIP_TOKEN' -ConfigValue $cfg.Token -Default '')
    $hb = 0
    if (-not [int]::TryParse([string](Resolve-DXSetting -ParamValue $HeartbeatHours -EnvName 'DX_CFIP_HEARTBEATHOURS' -ConfigValue $cfg.HeartbeatHours -Default 6), [ref]$hb) -or $hb -lt 1) {
        Exit-Collector 1 'HeartbeatHours must be a whole number >= 1'; return
    }
    $code = $code.Trim().ToUpperInvariant()
    if ($code -notmatch '^[A-Z0-9][A-Z0-9_-]{1,31}$') { Exit-Collector 1 'client code missing or invalid (2-32 chars: A-Z 0-9 _ -)'; return }
    if ($url -notmatch '^https://[^\s/]+/' -and -not ($AllowHttp -and $url -match '^http://[^\s/]+/')) {
        Exit-Collector 1 'report URL missing or not https:// (e.g. https://cfip.example.com.au/report)'; return
    }
    if ($tok.Length -lt 20) { Exit-Collector 1 'report token missing or too short'; return }
    # powershell.exe -File passes '-IpProviders a,b' as ONE string: split on , ; and whitespace
    $IpProviders = @($IpProviders | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ })
    if ($IpProviders.Count -eq 0) { $IpProviders = $DefaultProviders }

    Enable-DXTlsProtocol
    $found = Get-DXPublicIPv4 -Providers $IpProviders -Timeout $TimeoutSec
    $ip = $null
    if ($found) { $ip = $found.Ip } else { Write-DXLog 'no provider returned a valid public IPv4; the server will use the source address' 'WARN' }

    if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force | Out-Null }
    $statePath = Join-Path $StateDir 'cfip-collector-state.json'
    $state = $null
    if (Test-Path -LiteralPath $statePath) {
        try { $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } catch { $state = $null }
    }
    $nowUtc = (Get-Date).ToUniversalTime()
    $due = $true
    $reason = 'first run'
    if ($Force) { $reason = 'forced' }
    elseif (-not $ip) { $reason = 'IP unknown locally' }
    elseif ($state -and $state.Ip) {
        $last = [datetime]::MinValue
        $parsed = [datetime]::TryParse([string]$state.LastReportUtc, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$last)
        if ($state.Ip -ne $ip) { $reason = "IP changed $($state.Ip) -> $ip" }
        elseif (-not $parsed -or ($nowUtc - $last).TotalHours -ge $hb) { $reason = "heartbeat (${hb}h)" }
        else { $due = $false }
    }
    if (-not $due) { Exit-Collector 0 "IP $ip unchanged, last report $($state.LastReportUtc) UTC, heartbeat not due"; return }
    if ($DryRun) { Exit-Collector 0 "dry-run: would report $ip for $code ($reason)"; return }

    $body = @{ client = $code; ip = $ip; hostname = [Environment]::MachineName; version = $ScriptVersion } | ConvertTo-Json -Compress
    Write-DXLog "reporting $code ip=$ip ($reason) to $url"
    try {
        $resp = Invoke-WebRequest -Uri $url -Method Post -UseBasicParsing -TimeoutSec ($TimeoutSec * 2) -ContentType 'application/json' `
            -Body ([Text.Encoding]::UTF8.GetBytes($body)) -Headers @{ Authorization = "Bearer $tok"; 'User-Agent' = "dx-cfip-collector/$ScriptVersion" }
        $result = $resp.Content | ConvertFrom-Json
    }
    catch {
        $status = Get-DXHttpStatus $_
        if ($status -eq 401 -or $status -eq 403) { Exit-Collector 4 "report rejected HTTP $status (token wrong/rotated, client disabled or IP not allowed)"; return }
        if ($status -eq 422) { Exit-Collector 2 'server could not determine a public IPv4 either (HTTP 422)'; return }
        if ($status -ge 400 -and $status -lt 500 -and $status -ne 429) { Exit-Collector 5 "report rejected HTTP $status"; return }
        $why = $_.Exception.Message
        if ($status) { $why = "HTTP $status" }
        Exit-Collector 3 "report failed: $why"; return
    }
    $saved = @{ Ip = [string]$result.ip; LastReportUtc = $nowUtc.ToString('o'); LastStatus = [string]$result.status; ObservedIp = [string]$result.observed_ip }
    if ($ip) { $saved.Ip = $ip }
    $saved | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
    if ($ip -and $result.ip -and $result.ip -ne $ip) {
        Write-DXLog "server recorded $($result.ip) (it saw the request from $($result.observed_ip)); local detection said $ip" 'WARN'
    }
    Exit-Collector 0 "reported: server status=$($result.status) ip=$($result.ip)"
}

# Pester tests for the DX CF-IP collector + installer bundle. Run: tools/Invoke-Tests.ps1
BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Collector = Join-Path $Root 'collector/Invoke-DXCfipCollector.ps1'
    $script:Python = $env:CFIP_TEST_PYTHON
    if (-not $Python) { $script:Python = 'python3' }
    $script:InfoFile = Join-Path ([IO.Path]::GetTempPath()) ("cfip-harness-{0}.json" -f [guid]::NewGuid())
    $psi = New-Object Diagnostics.ProcessStartInfo($Python, "`"$(Join-Path $PSScriptRoot 'harness.py')`" `"$InfoFile`"")
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $script:Harness = [Diagnostics.Process]::Start($psi)
    $deadline = (Get-Date).AddSeconds(20)
    while (-not (Test-Path $InfoFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }
    $script:Info = Get-Content $InfoFile -Raw | ConvertFrom-Json
    $script:Pwsh = (Get-Process -Id $PID).Path

    function script:Invoke-Collector([string[]]$Providers, [string]$Url = $Info.report_url, [string]$Tok = $Info.token,
        [string]$Code = 'ACME', [string]$State, [string[]]$Extra = @()) {
        $provUrls = @($Providers | ForEach-Object { "$($Info.providers)/ip/$_" })
        $argList = @('-NoProfile', '-NonInteractive', '-File', $Collector, '-ClientCode', $Code, '-ReportUrl', $Url,
            '-Token', $Tok, '-StateDir', $State, '-LogDir', (Join-Path $State 'logs'), '-ConfigPath', (Join-Path $State 'none.json'),
            '-TimeoutSec', '3', '-AllowHttp', '-IpProviders', ($provUrls -join ',')) + $Extra
        $out = & $Pwsh @argList 2>&1 | Out-String
        return [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
    }
    function script:Get-ServerClient { (Get-Content (Join-Path $Info.data_dir 'state.json') -Raw | ConvertFrom-Json).clients.ACME }
    function script:New-StateDir { $d = Join-Path ([IO.Path]::GetTempPath()) ("cfip-st-{0}" -f [guid]::NewGuid()); New-Item -ItemType Directory $d | Out-Null; $d }
}

AfterAll {
    if ($Harness -and -not $Harness.HasExited) { $Harness.StandardInput.Close(); if (-not $Harness.WaitForExit(5000)) { $Harness.Kill() } }
    Remove-Item $InfoFile -ErrorAction SilentlyContinue
}

Describe 'IP detection, fallback and validation' {
    It 'uses the first provider when valid and reports it' {
        $st = New-StateDir
        $r = Invoke-Collector -Providers 'good' -State $st
        $r.Code | Should -Be 0
        $r.Out | Should -Match 'public IPv4 9\.9\.9\.9'
        (Get-ServerClient).ip | Should -Be '9.9.9.9'
    }
    It 'falls back past <bad> to the next provider' -ForEach @(
        @{ bad = '500' }, @{ bad = 'garbage' }, @{ bad = 'private' }, @{ bad = 'cgnat' }, @{ bad = 'doc' },
        @{ bad = 'v6' }, @{ bad = 'multi' }, @{ bad = 'leading0' }, @{ bad = 'missing404' }) {
        $st = New-StateDir
        $r = Invoke-Collector -Providers @($bad, 'good2') -State $st -Extra @('-DryRun')
        $r.Code | Should -Be 0
        $r.Out | Should -Match "provider .*/ip/$bad (failed|returned)"
        $r.Out | Should -Match 'public IPv4 149\.112\.112\.112'
    }
    It 'falls back after a timeout' {
        $st = New-StateDir
        $r = Invoke-Collector -Providers @('slow', 'good') -State $st -Extra @('-DryRun')
        $r.Code | Should -Be 0
        $r.Out | Should -Match 'public IPv4 9\.9\.9\.9'
    }
    It 'exits 2 when no provider works and the server cannot determine the IP either' {
        $st = New-StateDir
        $r = Invoke-Collector -Providers @('500', 'private') -State $st
        $r.Code | Should -Be 2
    }
}

Describe 'Reporting, heartbeat and auth' {
    It 'skips the report when unchanged and heartbeat not due, reports with -Force' {
        $st = New-StateDir
        (Invoke-Collector -Providers 'good' -State $st).Code | Should -Be 0
        $seen1 = (Get-ServerClient).last_seen
        Start-Sleep -Milliseconds 1100
        $r = Invoke-Collector -Providers 'good' -State $st
        $r.Code | Should -Be 0
        $r.Out | Should -Match 'heartbeat not due'
        (Get-ServerClient).last_seen | Should -Be $seen1
        (Invoke-Collector -Providers 'good' -State $st -Extra @('-Force')).Code | Should -Be 0
        (Get-ServerClient).last_seen | Should -BeGreaterThan $seen1
    }
    It 'reports when the heartbeat is due' {
        $st = New-StateDir
        Invoke-Collector -Providers 'good' -State $st | Out-Null
        $sf = Join-Path $st 'cfip-collector-state.json'
        $s = Get-Content $sf -Raw | ConvertFrom-Json
        $s.LastReportUtc = (Get-Date).ToUniversalTime().AddHours(-7).ToString('o')
        $s | ConvertTo-Json | Set-Content $sf
        $r = Invoke-Collector -Providers 'good' -State $st
        $r.Out | Should -Match 'heartbeat \(6h\)'
    }
    It 'reports immediately when the IP changes' {
        $st = New-StateDir
        Invoke-Collector -Providers 'good' -State $st | Out-Null
        $r = Invoke-Collector -Providers 'changed' -State $st
        $r.Code | Should -Be 0
        $r.Out | Should -Match 'IP changed 9\.9\.9\.9 -> 1\.1\.1\.1'
        (Get-ServerClient).ip | Should -Be '1.1.1.1'
        Invoke-Collector -Providers 'good' -State $st -Extra @('-Force') | Out-Null
    }
    It 'exits 4 on a bad token and never logs the token' {
        $st = New-StateDir
        $bad = 'x' * 43
        $r = Invoke-Collector -Providers 'good' -State $st -Tok $bad
        $r.Code | Should -Be 4
        $r.Out | Should -Not -Match $bad
        (Get-Content (Join-Path $st 'logs/DX-CFIP-Collector.log') -Raw) | Should -Not -Match $bad
    }
    It 'never writes the good token to console or log' {
        $st = New-StateDir
        $r = Invoke-Collector -Providers 'good' -State $st -Extra @('-Force')
        $r.Out.Contains($Info.token) | Should -BeFalse
        (Get-Content (Join-Path $st 'logs/DX-CFIP-Collector.log') -Raw).Contains($Info.token) | Should -BeFalse
    }
    It 'exits 4 for a client code the token does not belong to' {
        (Invoke-Collector -Providers 'good' -State (New-StateDir) -Code 'OTHER').Code | Should -Be 4
    }
    It 'exits 3 when the server is unreachable' {
        (Invoke-Collector -Providers 'good' -State (New-StateDir) -Url 'http://127.0.0.1:1/report').Code | Should -Be 3
    }
    It 'exits 3 on HTTP 5xx and 5 on HTTP 400' {
        (Invoke-Collector -Providers 'good' -State (New-StateDir) -Url "$($Info.providers)/report500").Code | Should -Be 3
        (Invoke-Collector -Providers 'good' -State (New-StateDir) -Url "$($Info.providers)/report400").Code | Should -Be 5
    }
    It 'dry-run does not report' {
        $st = New-StateDir
        $before = (Get-ServerClient).last_seen
        $r = Invoke-Collector -Providers 'good' -State $st -Extra @('-DryRun')
        $r.Out | Should -Match 'dry-run: would report 9\.9\.9\.9'
        (Get-ServerClient).last_seen | Should -Be $before
    }
}

Describe 'Configuration' {
    It 'exits 1 for <name>' -ForEach @(
        @{ name = 'missing client code'; code = ''; url = 'https://x.example/report'; tok = ('t' * 30); extra = @() },
        @{ name = 'bad client code'; code = 'bad code!'; url = 'https://x.example/report'; tok = ('t' * 30); extra = @() },
        @{ name = 'http url without -AllowHttp'; code = 'ACME'; url = 'http://x.example/report'; tok = ('t' * 30); extra = @('noallow') },
        @{ name = 'short token'; code = 'ACME'; url = 'https://x.example/report'; tok = 'short'; extra = @() }) {
        $st = New-StateDir
        $argList = @('-NoProfile', '-NonInteractive', '-File', $Collector, '-ClientCode', $code, '-ReportUrl', $url, '-Token', $tok,
            '-StateDir', $st, '-LogDir', $st, '-ConfigPath', (Join-Path $st 'none.json'))
        if ($extra -notcontains 'noallow') { $argList += '-AllowHttp' }
        & $Pwsh @argList *> $null
        $LASTEXITCODE | Should -Be 1
    }
    It 'reads client code, URL and token from the config file' {
        $st = New-StateDir
        $cfgPath = Join-Path $st 'cfip-collector.json'
        @{ ClientCode = 'acme'; ReportUrl = $Info.report_url; Token = $Info.token; HeartbeatHours = 6 } | ConvertTo-Json | Set-Content $cfgPath
        $out = & $Pwsh -NoProfile -NonInteractive -File $Collector -ConfigPath $cfgPath -StateDir $st -LogDir $st -AllowHttp -Force `
            -IpProviders "$($Info.providers)/ip/good" 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $out | Should -Match 'reported: server status='
    }
    It 'reads settings from DX_CFIP_* environment variables' {
        $st = New-StateDir
        $env:DX_CFIP_CLIENTCODE = 'ACME'; $env:DX_CFIP_REPORTURL = $Info.report_url; $env:DX_CFIP_TOKEN = $Info.token
        try {
            & $Pwsh -NoProfile -NonInteractive -File $Collector -StateDir $st -LogDir $st -ConfigPath (Join-Path $st 'none.json') `
                -AllowHttp -Force -IpProviders "$($Info.providers)/ip/good" *> $null
            $LASTEXITCODE | Should -Be 0
        }
        finally { Remove-Item Env:DX_CFIP_CLIENTCODE, Env:DX_CFIP_REPORTURL, Env:DX_CFIP_TOKEN }
    }
}

Describe 'Installer bundle and irm|iex safety' {
    It 'bundle builds, parses and embeds the collector' {
        $out = Join-Path ([IO.Path]::GetTempPath()) ("cfip-dist-{0}" -f [guid]::NewGuid())
        & $Pwsh -NoProfile -File (Join-Path $Root 'tools/Build-Bundle.ps1') -OutDir $out | Out-Null
        $LASTEXITCODE | Should -Be 0
        $b = Get-Content (Join-Path $out 'Install-DXCfipCollector.bundle.ps1') -Raw
        $b | Should -Match "EmbeddedCollector = @'"
        $b | Should -Match "EmbeddedLib = @'"
        $b | Should -Match 'DX Cloudflare trusted-IP collector'
    }
    It 'installer refuses to run off Windows with exit 1 (no changes)' -Skip:($env:OS -eq 'Windows_NT') {
        & $Pwsh -NoProfile -NonInteractive -File (Join-Path $Root 'collector/Install-DXCfipCollector.ps1') -ClientCode ACME *> $null
        $LASTEXITCODE | Should -Be 1
    }
    It '<file> wraps its body in & { } and only exits when non-interactive' -ForEach @(
        @{ file = 'collector/Invoke-DXCfipCollector.ps1' }, @{ file = 'collector/Install-DXCfipCollector.ps1' }, @{ file = 'install.ps1' }) {
        $t = Get-Content (Join-Path $Root $file) -Raw
        $t | Should -Match '(?m)^& \{'
        $t | Should -Match 'UserInteractive'
        ([regex]::Matches($t, '(?m)^\s*exit\b')).Count | Should -Be 1   # the single guarded exit
    }
    It 'irm|iex style scriptblock invocation in an interactive-looking session sets LASTEXITCODE without killing the host' {
        $sb = [scriptblock]::Create((Get-Content $Collector -Raw))
        $global:LASTEXITCODE = 99
        # -NonInteractive in this host's command line means exit would fire; run in a child to stay safe
        $code = "& ([scriptblock]::Create((Get-Content '$Collector' -Raw))) -ClientCode '' -ConfigPath none.json -LogDir '$([IO.Path]::GetTempPath())' ; 'still-alive:' + `$LASTEXITCODE"
        $null = $sb
        $out = & $Pwsh -NoProfile -Command $code 2>&1 | Out-String
        # With -Command the guard treats the session as non-interactive and exits 1 (RMM behaviour)
        $LASTEXITCODE | Should -Be 1
        $out | Should -Not -Match 'still-alive'
    }
}

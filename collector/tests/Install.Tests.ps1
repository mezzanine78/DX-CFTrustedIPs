# Pester tests for the root install.ps1 one-liner (and the shared DXCfip.Install.ps1 / N-central installer).
# Every install runs in a CHILD pwsh fed through stdin - the same as a technician's interactive console - using
# the real `irm <url>/install.ps1 | iex` against a local HTTP server. Windows-only actions (elevation check, ACL,
# scheduled task, first run) are replaced through $global:DXCfipOpsOverride and recorded to a log file.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'Test seam')]
param()
BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Pwsh = (Get-Process -Id $PID).Path
    $script:Python = $env:CFIP_TEST_PYTHON
    if (-not $Python) { $script:Python = 'python3' }
    $script:EnvTok = 'EnvTok_' + ('a' * 36)
    $script:PromptTok = 'PromptTok_' + ('b' * 33)
    $script:Servers = New-Object System.Collections.ArrayList

    function script:New-TempDir { $d = Join-Path ([IO.Path]::GetTempPath()) ("cfip-it-{0}" -f [guid]::NewGuid()); New-Item -ItemType Directory $d | Out-Null; $d }

    # Serve a copy of the repo (optionally tampered) and return its URL
    function script:Start-RepoServer([scriptblock]$Tamper) {
        $dir = New-TempDir
        Copy-Item (Join-Path $Root 'install.ps1') $dir
        New-Item -ItemType Directory (Join-Path $dir 'collector') | Out-Null
        Copy-Item (Join-Path $Root 'collector/DXCfip.Install.ps1'), (Join-Path $Root 'collector/Invoke-DXCfipCollector.ps1') (Join-Path $dir 'collector')
        if ($Tamper) { & $Tamper $dir }
        $info = Join-Path $dir '.info.json'
        $psi = New-Object Diagnostics.ProcessStartInfo($Python, "`"$(Join-Path $PSScriptRoot 'serve_dir.py')`" `"$dir`" `"$info`"")
        $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true
        [void]$Servers.Add([Diagnostics.Process]::Start($psi))
        $deadline = (Get-Date).AddSeconds(15)
        while (-not (Test-Path $info) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 100 }
        return (Get-Content $info -Raw | ConvertFrom-Json).url
    }

    $script:RepoUrl = Start-RepoServer

    # Run $Body in a child pwsh fed via stdin. Returns output text + the child's exit code.
    function script:Invoke-Child([string]$Body, [string[]]$ExtraArgs = @()) {
        $psi = New-Object Diagnostics.ProcessStartInfo($Pwsh, ((@('-NoProfile', '-NoLogo') + $ExtraArgs) -join ' '))
        $psi.UseShellExecute = $false; $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        # The body goes in a file and stdin carries one dot-source line: the interactive host echoes stdin and
        # only runs a multi-line block after a blank line, and the file keeps secrets out of that echo.
        $file = Join-Path (New-TempDir) 'child.ps1'
        Set-Content -LiteralPath $file -Value $Body
        $p = [Diagnostics.Process]::Start($psi)
        $errTask = $p.StandardError.ReadToEndAsync()
        $p.StandardInput.WriteLine(". '$file'")
        $p.StandardInput.Close()
        $out = $p.StandardOutput.ReadToEnd()
        $p.WaitForExit()
        return [pscustomobject]@{ Out = $out + $errTask.Result; ExitCode = $p.ExitCode }
    }

    # Child-script prologue: fake OS actions + env inputs. $Ops overrides individual fakes.
    function script:New-Prologue([hashtable]$Env, [string]$FakeLog, [string]$Ops = '') {
        $lines = @(
            "`$env:FAKE_LOG = '$FakeLog'",
            '$global:DXCfipOpsOverride = @{',
            '  IsWindows = { $true }; IsElevated = { $true }; CanPrompt = { $false }',
            "  ReadToken = { `$s = New-Object Security.SecureString; foreach (`$c in '$PromptTok'.ToCharArray()) { `$s.AppendChar(`$c) }; `$s }",
            '  ProtectPath = { param($Path, $Directory) Add-Content $env:FAKE_LOG "acl:$Path" }',
            '  RegisterTask = { param($Arguments) Add-Content $env:FAKE_LOG "register:$Arguments" }',
            '  UnregisterTask = { Add-Content $env:FAKE_LOG "unregister"; $true }',
            '  RunCollector = { param($Arguments) Add-Content $env:FAKE_LOG "run:$Arguments"; 0 }',
            '  GetTaskArguments = { [string]$env:FAKE_TASKARGS }; Is64BitOS = { $true }',
            '  GetRegDword = { param($Path, $Name) $null }',
            '  SetRegDword = { param($Path, $Name, $Value) Add-Content $env:FAKE_LOG "reg:$Path\$Name=$Value" }',
            '}')
        if ($Ops) { $lines += $Ops }
        foreach ($k in $Env.Keys) { $lines += "`$env:$k = '$($Env[$k])'" }
        return ($lines -join "`n")
    }

    function script:Invoke-OneLiner([hashtable]$Env, [string]$Ops = '', [string]$Url = $RepoUrl, [string[]]$ExtraArgs = @(), [string]$Pre = '', [string]$Post = '') {
        $tmp = New-TempDir
        $fake = Join-Path $tmp 'fake.log'
        $e = @{ DX_CFIP_ROOTDIR = (Join-Path $tmp 'DX'); DX_CFIP_LEGACYROOTDIR = (Join-Path $tmp 'OLDDX'); DX_CFIP_REPOURL = $Url }
        foreach ($k in $Env.Keys) { $e[$k] = $Env[$k] }
        $body = (New-Prologue -Env $e -FakeLog $fake -Ops $Ops) + "`n$Pre`nirm '$Url/install.ps1' | iex`n" +
        "`"RC=`$LASTEXITCODE`"; `"TOKENENV=[`$env:DX_CFIP_TOKEN]`"`n$Post`n'ALIVE'"
        $r = Invoke-Child -Body $body -ExtraArgs $ExtraArgs
        $cfgFile = Join-Path $tmp 'DX/Config/cfip-collector.json'
        $cfg = $null
        if (Test-Path $cfgFile) { $cfg = Get-Content $cfgFile -Raw | ConvertFrom-Json }
        $rc = $null
        if ($r.Out -match 'RC=(\d+)') { $rc = [int]$Matches[1] }
        $fakeText = ''
        if (Test-Path $fake) { $fakeText = Get-Content $fake -Raw }
        $tokEnv = '?'
        if ($r.Out -match 'TOKENENV=\[(.*)\]') { $tokEnv = $Matches[1] }
        return [pscustomobject]@{ Out = $r.Out; Rc = $rc; ExitCode = $r.ExitCode; Root = $tmp; Config = $cfg; Fake = $fakeText
            Alive = ($r.Out -match '(?m)^ALIVE'); TokenEnv = $tokEnv }
    }

    $script:Good = @{ DX_CFIP_CLIENTCODE = 'acme'; DX_CFIP_ENDPOINT = 'https://cfip.example.com.au'; DX_CFIP_TOKEN = $EnvTok }
}

AfterAll {
    foreach ($s in $Servers) { if (-not $s.HasExited) { $s.StandardInput.Close(); if (-not $s.WaitForExit(3000)) { $s.Kill() } } }
}

Describe 'install.ps1 via irm | iex' {
    It 'installs from env vars, keeps the host alive, clears the token env var' {
        $r = Invoke-OneLiner -Env $Good
        $r.Rc | Should -Be 0
        $r.Alive | Should -BeTrue
        $r.TokenEnv | Should -Be ''
        $r.Config.ClientCode | Should -Be 'ACME'
        $r.Config.ReportUrl | Should -Be 'https://cfip.example.com.au/report'
        $r.Config.Token | Should -Be $EnvTok
        $r.Config.HeartbeatHours | Should -Be 6
        (Get-Content (Join-Path $r.Root 'DX/Scripts/Invoke-DXCfipCollector.ps1') -Raw).Trim() |
            Should -Be (Get-Content (Join-Path $Root 'collector/Invoke-DXCfipCollector.ps1') -Raw).Trim()
        $r.Fake | Should -Match 'acl:.*DX[\\/]Config'
        $r.Fake | Should -Match 'register:.*-File ".*Invoke-DXCfipCollector\.ps1" -ConfigPath ".*cfip-collector\.json" -StateDir ".*State" -LogDir ".*Logs"'
        $r.Fake | Should -Match 'run:'
        $r.Out | Should -Match 'SHA256 OK'
        $r.Out | Should -Match ('install root ' + [regex]::Escape((Join-Path $r.Root 'DX')))   # DX_CFIP_ROOTDIR override
        $r.Fake | Should -Not -Match 'reg:'                                                    # DX_CFIP_FIXTLS off by default
        $r.Out.Contains($EnvTok) | Should -BeFalse
        $r.Fake.Contains($EnvTok) | Should -BeFalse
    }
    It 'also works as & ([scriptblock]::Create((irm ...)))' {
        $tmp = New-TempDir
        $e = @{ DX_CFIP_ROOTDIR = (Join-Path $tmp 'DX'); DX_CFIP_LEGACYROOTDIR = (Join-Path $tmp 'OLDDX'); DX_CFIP_REPOURL = $RepoUrl } + $Good
        $body = (New-Prologue -Env $e -FakeLog (Join-Path $tmp 'f.log')) + "`n& ([scriptblock]::Create((irm '$RepoUrl/install.ps1')))`n`"RC=`$LASTEXITCODE`"`n'ALIVE'"
        $out = (Invoke-Child -Body $body).Out
        $out | Should -Match 'RC=0'
        $out | Should -Match '(?m)^ALIVE'
    }
    It 'accepts DX_CFIP_REPORTURL with a path and a custom heartbeat' {
        $r = Invoke-OneLiner -Env @{ DX_CFIP_CLIENTCODE = 'BETA'; DX_CFIP_REPORTURL = 'https://cfip.example.com.au/report'; DX_CFIP_TOKEN = $EnvTok; DX_CFIP_HEARTBEATHOURS = '12' }
        $r.Rc | Should -Be 0
        $r.Config.HeartbeatHours | Should -Be 12
        $r.Config.ReportUrl | Should -Be 'https://cfip.example.com.au/report'
    }
    It 'DX_CFIP_FIXTLS=1 sets the 4 .NET TLS values (both registry views)' {
        $r = Invoke-OneLiner -Env ($Good + @{ DX_CFIP_FIXTLS = '1' })
        $r.Rc | Should -Be 0
        @([regex]::Matches($r.Fake, '(?m)^reg:.*=1')).Count | Should -Be 4
        $r.Fake | Should -Match 'WOW6432Node.*SchUseStrongCrypto'
        $r.Out | Should -Match 'New processes'
    }
    It 'migrates an install from the old root and reuses its token when DX_CFIP_TOKEN is empty' {
        $tmp = New-TempDir
        $old = Join-Path $tmp 'OLDDX'
        New-Item -ItemType Directory (Join-Path $old 'Config'), (Join-Path $old 'Scripts') -Force | Out-Null
        @{ ClientCode = 'ACME'; ReportUrl = 'https://cfip.example.com.au/report'; Token = $EnvTok; HeartbeatHours = 6 } | ConvertTo-Json |
            Set-Content (Join-Path $old 'Config/cfip-collector.json')
        Set-Content (Join-Path $old 'Scripts/Invoke-DXCfipCollector.ps1') '# old'
        $fake = Join-Path $tmp 'fake.log'
        $e = @{ DX_CFIP_ROOTDIR = (Join-Path $tmp 'DX'); DX_CFIP_LEGACYROOTDIR = $old; DX_CFIP_REPOURL = $RepoUrl
            DX_CFIP_CLIENTCODE = 'acme'; DX_CFIP_ENDPOINT = 'https://cfip.example.com.au' }
        $body = (New-Prologue -Env $e -FakeLog $fake) + "`nirm '$RepoUrl/install.ps1' | iex`n`"RC=`$LASTEXITCODE`""
        $out = (Invoke-Child -Body $body).Out
        $out | Should -Match 'RC=0'
        $out | Should -Match 'reusing the token'
        $out | Should -Match 'migration: done'
        (Get-Content (Join-Path $tmp 'DX/Config/cfip-collector.json') -Raw | ConvertFrom-Json).Token | Should -Be $EnvTok
        Test-Path $old | Should -BeFalse
        $out.Contains($EnvTok) | Should -BeFalse
    }
    It 'skips the first run with DX_CFIP_NORUNNOW=1' {
        $r = Invoke-OneLiner -Env ($Good + @{ DX_CFIP_NORUNNOW = '1' })
        $r.Rc | Should -Be 0
        $r.Fake | Should -Not -Match 'run:'
    }
    It 'returns 4 (task kept) when the first collector run fails' {
        $r = Invoke-OneLiner -Env $Good -Ops '$global:DXCfipOpsOverride.RunCollector = { param($Arguments) 3 }'
        $r.Rc | Should -Be 4
        $r.Fake | Should -Match 'register:'
    }
    It 'fails with 1 and writes nothing for <name>' -ForEach @(
        @{ name = 'missing client code'; envx = @{ DX_CFIP_ENDPOINT = 'https://cfip.example.com.au'; DX_CFIP_TOKEN = ('t' * 30) }; pat = 'DX_CFIP_CLIENTCODE' },
        @{ name = 'invalid client code'; envx = @{ DX_CFIP_CLIENTCODE = 'bad code'; DX_CFIP_ENDPOINT = 'https://cfip.example.com.au'; DX_CFIP_TOKEN = ('t' * 30) }; pat = 'DX_CFIP_CLIENTCODE' },
        @{ name = 'missing endpoint'; envx = @{ DX_CFIP_CLIENTCODE = 'ACME'; DX_CFIP_TOKEN = ('t' * 30) }; pat = 'DX_CFIP_ENDPOINT' },
        @{ name = 'http endpoint'; envx = @{ DX_CFIP_CLIENTCODE = 'ACME'; DX_CFIP_ENDPOINT = 'http://cfip.example.com.au'; DX_CFIP_TOKEN = ('t' * 30) }; pat = 'DX_CFIP_ENDPOINT' },
        @{ name = 'bad heartbeat'; envx = @{ DX_CFIP_CLIENTCODE = 'ACME'; DX_CFIP_ENDPOINT = 'https://h.example'; DX_CFIP_TOKEN = ('t' * 30); DX_CFIP_HEARTBEATHOURS = '0' }; pat = 'HEARTBEAT' },
        @{ name = 'malformed token'; envx = @{ DX_CFIP_CLIENTCODE = 'ACME'; DX_CFIP_ENDPOINT = 'https://h.example'; DX_CFIP_TOKEN = 'has spaces in it but long enough' }; pat = 'token' },
        @{ name = 'no token and cannot prompt'; envx = @{ DX_CFIP_CLIENTCODE = 'ACME'; DX_CFIP_ENDPOINT = 'https://h.example' }; pat = 'cannot prompt' }) {
        $r = Invoke-OneLiner -Env $envx
        $r.Rc | Should -Be 1
        $r.Alive | Should -BeTrue
        $r.Out | Should -Match $pat
        $r.Config | Should -BeNullOrEmpty
        $r.Fake | Should -Not -Match 'register:'
    }
    It 'prompts (hidden) when the token is empty and the session can prompt' {
        $r = Invoke-OneLiner -Env @{ DX_CFIP_CLIENTCODE = 'ACME'; DX_CFIP_ENDPOINT = 'https://cfip.example.com.au' } -Ops '$global:DXCfipOpsOverride.CanPrompt = { $true }'
        $r.Rc | Should -Be 0
        $r.Config.Token | Should -Be $PromptTok
        $r.Out.Contains($PromptTok) | Should -BeFalse
    }
    It 'fails with 1 when nothing is entered at the prompt' {
        $r = Invoke-OneLiner -Env @{ DX_CFIP_CLIENTCODE = 'ACME'; DX_CFIP_ENDPOINT = 'https://h.example' } `
            -Ops '$global:DXCfipOpsOverride.CanPrompt = { $true }; $global:DXCfipOpsOverride.ReadToken = { New-Object Security.SecureString }'
        $r.Rc | Should -Be 1
        $r.Out | Should -Match 'no token entered'
    }
    It 'not elevated: exits 2 with instructions, no prompt, nothing written, token env cleared' {
        $r = Invoke-OneLiner -Env $Good -Ops '$global:DXCfipOpsOverride.IsElevated = { $false }; $global:DXCfipOpsOverride.ReadToken = { throw "must not prompt" }'
        $r.Rc | Should -Be 2
        $r.Alive | Should -BeTrue
        $r.Out | Should -Match 'Run as administrator'
        $r.Config | Should -BeNullOrEmpty
        $r.TokenEnv | Should -Be ''
    }
    It 'not Windows: exits 1' {
        (Invoke-OneLiner -Env $Good -Ops '$global:DXCfipOpsOverride.IsWindows = { $false }').Rc | Should -Be 1
    }
    It 'uninstall removes task, collector, config and state but keeps logs' {
        $tmp = New-TempDir
        $e = @{ DX_CFIP_ROOTDIR = (Join-Path $tmp 'DX'); DX_CFIP_LEGACYROOTDIR = (Join-Path $tmp 'OLDDX'); DX_CFIP_REPOURL = $RepoUrl }
        $fake = Join-Path $tmp 'f.log'
        $body = (New-Prologue -Env ($e + $Good) -FakeLog $fake) + "`nirm '$RepoUrl/install.ps1' | iex`n" +
        "Set-Content '$tmp/DX/State/cfip-collector-state.json' '{}'; Set-Content '$tmp/DX/Logs/DX-CFIP-Collector.log' 'x'`n" +
        "`$env:DX_CFIP_UNINSTALL = '1'`nirm '$RepoUrl/install.ps1' | iex`n`"RC=`$LASTEXITCODE`"`n'ALIVE'"
        $out = (Invoke-Child -Body $body).Out
        $out | Should -Match 'RC=0'
        Get-Content $fake -Raw | Should -Match 'unregister'
        Test-Path "$tmp/DX/Scripts/Invoke-DXCfipCollector.ps1" | Should -BeFalse
        Test-Path "$tmp/DX/Config/cfip-collector.json" | Should -BeFalse
        Test-Path "$tmp/DX/State/cfip-collector-state.json" | Should -BeFalse
        Test-Path "$tmp/DX/Logs/DX-CFIP-Collector.log" | Should -BeTrue
    }
    It 'uninstall needs no client code or token' {
        $r = Invoke-OneLiner -Env @{ DX_CFIP_UNINSTALL = '1' }
        $r.Rc | Should -Be 0
        $r.Fake | Should -Match 'unregister'
    }
    It 'prompted token never appears in a transcript' {
        $tr = Join-Path (New-TempDir) 'transcript.txt'
        $r = Invoke-OneLiner -Env @{ DX_CFIP_CLIENTCODE = 'ACME'; DX_CFIP_ENDPOINT = 'https://cfip.example.com.au' } -Ops '$global:DXCfipOpsOverride.CanPrompt = { $true }' `
            -Pre "Start-Transcript -LiteralPath '$tr' | Out-Null" -Post 'Stop-Transcript | Out-Null'
        $r.Rc | Should -Be 0
        $t = Get-Content $tr -Raw
        $t | Should -Match 'install finished'
        $t.Contains($PromptTok) | Should -BeFalse
        $r.Config.Token | Should -Be $PromptTok
    }
    It 'env-var token never appears in a transcript started after it was set' {
        $tr = Join-Path (New-TempDir) 'transcript.txt'
        $r = Invoke-OneLiner -Env $Good -Pre "Start-Transcript -LiteralPath '$tr' | Out-Null" -Post 'Stop-Transcript | Out-Null'
        $r.Rc | Should -Be 0
        $t = Get-Content $tr -Raw
        $t | Should -Match 'install finished'
        $t.Contains($EnvTok) | Should -BeFalse
    }
}

Describe 'install.ps1 download verification' {
    It 'exits 3 and installs nothing when the collector hash does not match the pin' {
        $url = Start-RepoServer { param($d) Add-Content (Join-Path $d 'collector/Invoke-DXCfipCollector.ps1') '# tampered' }
        $r = Invoke-OneLiner -Env $Good -Url $url
        $r.Rc | Should -Be 3
        $r.Out | Should -Match 'SHA256 mismatch for collector/Invoke-DXCfipCollector.ps1'
        $r.Config | Should -BeNullOrEmpty
        $r.TokenEnv | Should -Be ''
    }
    It 'exits 3 when the shared install code hash does not match' {
        $url = Start-RepoServer { param($d) Add-Content (Join-Path $d 'collector/DXCfip.Install.ps1') '# tampered' }
        $r = Invoke-OneLiner -Env $Good -Url $url
        $r.Rc | Should -Be 3
        $r.Out | Should -Match 'SHA256 mismatch for collector/DXCfip.Install.ps1'
    }
    It 'without pins (dev build) still rejects a collector that does not parse' {
        $url = Start-RepoServer { param($d)
            $i = Join-Path $d 'install.ps1'
            (Get-Content $i -Raw) -replace "(?m)(^\s+'collector/[^']+'\s*=\s*)'[0-9A-F]+'", '$1''''' | Set-Content $i
            Add-Content (Join-Path $d 'collector/Invoke-DXCfipCollector.ps1') 'function broken {'
        }
        $r = Invoke-OneLiner -Env $Good -Url $url
        $r.Out | Should -Match 'no pinned SHA256'
        $r.Out | Should -Match 'does not parse'
        $r.Rc | Should -Be 3
    }
    It 'exits 3 when the download fails' {
        $tmp = New-TempDir
        $e = @{ DX_CFIP_ROOTDIR = (Join-Path $tmp 'DX'); DX_CFIP_LEGACYROOTDIR = (Join-Path $tmp 'OLDDX'); DX_CFIP_REPOURL = 'http://127.0.0.1:1' } + $Good
        $body = (New-Prologue -Env $e -FakeLog (Join-Path $tmp 'f.log')) + "`n(irm '$RepoUrl/install.ps1') | iex`n`"RC=`$LASTEXITCODE`"`n'ALIVE'"
        (Invoke-Child -Body $body).Out | Should -Match 'RC=3'
    }
    It 'rejects a non-https DX_CFIP_REPOURL with 1' {
        $tmp = New-TempDir
        $e = @{ DX_CFIP_ROOTDIR = (Join-Path $tmp 'DX'); DX_CFIP_LEGACYROOTDIR = (Join-Path $tmp 'OLDDX'); DX_CFIP_REPOURL = 'http://evil.example' } + $Good
        $body = (New-Prologue -Env $e -FakeLog (Join-Path $tmp 'f.log')) + "`nirm '$RepoUrl/install.ps1' | iex`n`"RC=`$LASTEXITCODE`"`n'ALIVE'"
        (Invoke-Child -Body $body).Out | Should -Match 'RC=1'
    }
    It 'pins in install.ps1 match the files in the repo' {
        $t = Get-Content (Join-Path $Root 'install.ps1') -Raw
        foreach ($rel in 'collector/DXCfip.Install.ps1', 'collector/Invoke-DXCfipCollector.ps1') {
            $t | Should -Match ([regex]::Escape("'$rel'") + "\s*=\s*'" + (Get-FileHash (Join-Path $Root $rel)).Hash + "'") -Because "run tools/Update-Pins.ps1 after changing $rel"
        }
    }
    It 'install.ps1 is ASCII-only, has no param() block and no BOM (safe for irm | iex on 5.1)' {
        $bytes = [IO.File]::ReadAllBytes((Join-Path $Root 'install.ps1'))
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
        $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'install.ps1'), [ref]$null, [ref]$null)
        $ast.ParamBlock | Should -BeNullOrEmpty
    }
}

Describe 'non-interactive (RMM) behaviour' {
    BeforeAll {
        # Exactly how an RMM runs it: powershell -NonInteractive -Command "...; irm <url> | iex"
        function script:Invoke-Rmm([hashtable]$Env, [string]$Ops = '') {
            $tmp = New-TempDir
            $e = @{ DX_CFIP_ROOTDIR = (Join-Path $tmp 'DX'); DX_CFIP_LEGACYROOTDIR = (Join-Path $tmp 'OLDDX'); DX_CFIP_REPOURL = $RepoUrl } + $Env
            $pro = Join-Path $tmp 'prologue.ps1'
            Set-Content -LiteralPath $pro -Value (New-Prologue -Env $e -FakeLog (Join-Path $tmp 'f.log') -Ops $Ops)
            $out = & $Pwsh -NoProfile -NonInteractive -Command ". '$pro'; irm '$RepoUrl/install.ps1' | iex; 'ALIVE'" 2>&1 | Out-String
            return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Out = $out; Tmp = $tmp }
        }
    }
    It 'calls exit with the code (2, not elevated) under -NonInteractive -Command' {
        $r = Invoke-Rmm -Env $Good -Ops '$global:DXCfipOpsOverride.IsElevated = { $false }'
        $r.ExitCode | Should -Be 2
        $r.Out | Should -Not -Match '(?m)^ALIVE'
    }
    It 'exits 0 under -NonInteractive -Command when the install succeeds' {
        $r = Invoke-Rmm -Env $Good
        $r.ExitCode | Should -Be 0
        (Get-Content (Join-Path $r.Tmp 'DX/Config/cfip-collector.json') -Raw | ConvertFrom-Json).ClientCode | Should -Be 'ACME'
        $r.Out.Contains($EnvTok) | Should -BeFalse
    }
    It 'does not prompt under -NonInteractive even if the real CanPrompt is used' {
        $r = Invoke-Rmm -Env @{ DX_CFIP_CLIENTCODE = 'ACME'; DX_CFIP_ENDPOINT = 'https://h.example' } `
            -Ops '$global:DXCfipOpsOverride.Remove("CanPrompt"); $global:DXCfipOpsOverride.ReadToken = { throw "must not prompt" }'
        $r.ExitCode | Should -Be 1
        $r.Out | Should -Match 'cannot prompt'
    }
}

Describe 'N-central installer shares the same code' {
    It '<variant> installs with the shared library and exits with its code' -ForEach @(
        @{ variant = 'source tree'; script = 'collector/Install-DXCfipCollector.ps1' },
        @{ variant = 'bundle'; script = 'BUNDLE' }) {
        $tmp = New-TempDir
        $path = Join-Path $Root $script
        if ($script -eq 'BUNDLE') {
            $dist = New-TempDir
            & $Pwsh -NoProfile -File (Join-Path $Root 'tools/Build-Bundle.ps1') -OutDir $dist | Out-Null
            $path = Join-Path $dist 'Install-DXCfipCollector.bundle.ps1'   # alone in its folder: needs no neighbour files
        }
        $body = (New-Prologue -Env @{} -FakeLog (Join-Path $tmp 'f.log')) +
        "`n& '$path' -ClientCode acme -ReportUrl https://h.example/report -Token $EnvTok -RootDir '$tmp/DX' -LegacyRootDir '$tmp/OLDDX'`n`"RC=`$LASTEXITCODE`""
        $r = Invoke-Child -Body $body -ExtraArgs @('-NonInteractive')
        $r.Out | Should -Match 'RC=0'
        $r.Out | Should -Match 'install finished'
        (Get-Content "$tmp/DX/Config/cfip-collector.json" -Raw | ConvertFrom-Json).ClientCode | Should -Be 'ACME'
        Get-Content (Join-Path $tmp 'f.log') -Raw | Should -Match 'register:.*-ConfigPath'
        $r.Out.Contains($EnvTok) | Should -BeFalse
    }
    It 'N-central installer -Uninstall works through the shared code' {
        $tmp = New-TempDir
        $body = (New-Prologue -Env @{} -FakeLog (Join-Path $tmp 'f.log')) +
        "`n& '$(Join-Path $Root 'collector/Install-DXCfipCollector.ps1')' -Uninstall -RootDir '$tmp/DX' -LegacyRootDir '$tmp/OLDDX'`n`"RC=`$LASTEXITCODE`""
        (Invoke-Child -Body $body -ExtraArgs @('-NonInteractive')).Out | Should -Match 'RC=0'
        Get-Content (Join-Path $tmp 'f.log') -Raw | Should -Match 'unregister'
    }
    It 'N-central installer returns 2 when not elevated' {
        $tmp = New-TempDir
        $body = (New-Prologue -Env @{} -FakeLog (Join-Path $tmp 'f.log') -Ops '$global:DXCfipOpsOverride.IsElevated = { $false }') +
        "`n& '$(Join-Path $Root 'collector/Install-DXCfipCollector.ps1')' -ClientCode ACME -ReportUrl https://h.example/report -Token $EnvTok -RootDir '$tmp/DX' -LegacyRootDir '$tmp/OLDDX'`n`"RC=`$LASTEXITCODE`""
        (Invoke-Child -Body $body).Out | Should -Match 'RC=2'
        Test-Path "$tmp/DX/Config/cfip-collector.json" | Should -BeFalse
    }
}

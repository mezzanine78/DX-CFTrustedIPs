# Unit tests for the collector's TLS handling. The collector's body runs inside & { }, so the functions under test
# are lifted out of the script's AST and defined here; Write-DXLog is replaced by a recorder.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Loads functions from the collector AST')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester scopes')]
param()
BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Path = Join-Path $Root 'collector/Invoke-DXCfipCollector.ps1'
    $script:Ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    $script:Funcs = $Ast.FindAll({ param($a) $a -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)
    foreach ($n in 'Get-DXTlsProtocolSet', 'Test-DXTlsFailure', 'ConvertTo-DXNetFxVersion', 'Get-DXTlsAdvice', 'Get-DXPlatformInfo', 'Write-DXTlsDiagnostic') {
        $f = $Funcs | Where-Object Name -eq $n
        if (-not $f) { throw "function $n not found in the collector" }
        Invoke-Expression ($f.Extent.Text -replace "^function $n", "function script:$n")
    }
    $script:Logged = New-Object System.Collections.ArrayList
    function script:Write-DXLog([string]$Msg, [string]$Level = 'INFO') { [void]$script:Logged.Add("$Level $Msg") }
    $script:Names = [enum]::GetNames([Net.SecurityProtocolType])
}

Describe 'collector TLS protocols' {
    It 'always adds Tls12 and keeps the existing flags' {
        $p = Get-DXTlsProtocolSet -Current 192 -Build 9600 -IsWin $true -Names $Names
        ($p -band 3072) | Should -Be 3072
        ($p -band 192) | Should -Be 192
        ($p -band 12288) | Should -Be 0
    }
    It 'adds Tls13 on Windows build <b> = <want> (enum present)' -ForEach @(
        @{ b = 9600; want = $false }, @{ b = 17763; want = $false }, @{ b = 20348; want = $true }, @{ b = 26100; want = $true }) {
        $p = Get-DXTlsProtocolSet -Current 0 -Build $b -IsWin $true -Names @('Tls12', 'Tls13')
        [bool]($p -band 12288) | Should -Be $want
    }
    It 'never adds Tls13 when this .NET has no Tls13 enum value (old PS 5.1 / .NET)' {
        $p = Get-DXTlsProtocolSet -Current 0 -Build 26100 -IsWin $true -Names @('Ssl3', 'Tls', 'Tls11', 'Tls12')
        ($p -band 12288) | Should -Be 0
        ($p -band 3072) | Should -Be 3072
    }
    It 'adds Tls13 off Windows when available' {
        $p = Get-DXTlsProtocolSet -Current 0 -Build 0 -IsWin $false -Names $Names
        [bool]($p -band 12288) | Should -Be ($Names -contains 'Tls13')
    }
    It 'sets the protocols in the main flow before any web call' {
        # main-flow calls only (not inside a function definition)
        $main = @($Ast.FindAll({ param($a) $a -is [Management.Automation.Language.CommandAst] }, $true) | Where-Object {
                $c = $_; -not @($Funcs | Where-Object { $_.Extent.StartOffset -lt $c.Extent.StartOffset -and $_.Extent.EndOffset -ge $c.Extent.EndOffset }).Count })
        $tls = ($main | Where-Object { $_.GetCommandName() -eq 'Enable-DXTlsProtocol' } | Select-Object -First 1).Extent.StartOffset
        $tls | Should -Not -BeNullOrEmpty
        foreach ($web in 'Get-DXPublicIPv4', 'Invoke-WebRequest') {
            $first = ($main | Where-Object { $_.GetCommandName() -eq $web } | Select-Object -First 1).Extent.StartOffset
            $first | Should -BeGreaterThan $tls -Because "$web must run after Enable-DXTlsProtocol"
        }
    }
}

Describe 'TLS failure detection' {
    It 'detects <name>' -ForEach @(
        @{ name = 'WebException SecureChannelFailure (PS 5.1)'; ex = { New-Object Net.WebException('The request was aborted: Could not create SSL/TLS secure channel.', [Net.WebExceptionStatus]::SecureChannelFailure) } },
        @{ name = 'inner AuthenticationException (PS 7)'; ex = { New-Object Net.Http.HttpRequestException('outer', (New-Object Security.Authentication.AuthenticationException('frame'))) } },
        @{ name = 'message only'; ex = { New-Object Exception('Could not create SSL/TLS secure channel.') } },
        @{ name = 'SSL connection message'; ex = { New-Object Exception('The SSL connection could not be established, see inner exception.') } }) {
        Test-DXTlsFailure (& $ex) | Should -BeTrue
    }
    It 'ignores <name>' -ForEach @(
        @{ name = 'connect failure'; ex = { New-Object Net.WebException('Unable to connect to the remote server', [Net.WebExceptionStatus]::ConnectFailure) } },
        @{ name = 'timeout'; ex = { New-Object TimeoutException('The operation has timed out.') } },
        @{ name = 'null'; ex = { $null } }) {
        Test-DXTlsFailure (& $ex) | Should -BeFalse
    }
}

Describe 'TLS diagnostics' {
    It 'maps .NET release <r> to <v>' -ForEach @(
        @{ r = 533320; v = '4.8.1' }, @{ r = 528040; v = '4.8' }, @{ r = 461808; v = '4.7.2' }, @{ r = 393295; v = '4.6' },
        @{ r = 378389; v = '4.5' }, @{ r = 1; v = 'older than 4.5' }, @{ r = 0; v = 'not found' }) {
        ConvertTo-DXNetFxVersion $r | Should -Be $v
    }
    It 'reports OS, build, PS, .NET and the registry hint' {
        $a = (Get-DXTlsAdvice ([pscustomobject]@{ Caption = 'Microsoft Windows Server 2019 Standard'; Build = 17763; PSVersion = '5.1.17763.316'; NetRelease = 528049 })) -join "`n"
        $a | Should -Match 'Windows Server 2019 Standard \(build 17763\)'
        $a | Should -Match 'PowerShell 5\.1\.17763\.316'
        $a | Should -Match '\.NET Framework 4\.8 \(release 528049\)'
        $a | Should -Match 'SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1'
        $a | Should -Match ([regex]::Escape('HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'))
        $a | Should -Match ([regex]::Escape('HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'))
        $a | Should -Match 'DX_CFIP_FIXTLS=1'
        $a | Should -Not -Match 'ECDHE'
    }
    It 'adds the 2012 R2 / 8.1 (build 9600) advice' {
        $a = (Get-DXTlsAdvice ([pscustomobject]@{ Caption = 'Microsoft Windows Server 2012 R2 Standard'; Build = 9600; PSVersion = '5.1'; NetRelease = 461814 })) -join "`n"
        $a | Should -Match 'build 9600'
        $a | Should -Match 'KB3140245'
        $a | Should -Match 'ECDHE-GCM'
    }
    It 'logs the diagnostics once per run' {
        $script:Logged.Clear()
        $script:TlsDiagDone = $false
        Write-DXTlsDiagnostic; Write-DXTlsDiagnostic
        @($script:Logged | Where-Object { $_ -match 'TLS hint: let \.NET' }).Count | Should -Be 1
    }
}

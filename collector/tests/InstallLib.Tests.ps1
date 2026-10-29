# Unit tests for the shared install library (collector/DXCfip.Install.ps1): default root, override, ACLs by SID,
# migration from the old C:\DX root, uninstall of both roots, and the opt-in .NET TLS registry fix.
# The library is dot-sourced with fake OS actions ($global:DXCfipOpsOverride); file work happens in TestDrive.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification = 'Test seam')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Pester scopes')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Get-Acl/Set-Acl stubs (absent on Linux) so Pester can mock them')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Test stub')]
param()
BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CollectorText = Get-Content (Join-Path $Root 'collector/Invoke-DXCfipCollector.ps1') -Raw
    $script:Tok = 'Tok_' + ('z' * 40)
    $global:DXFake = New-Object System.Collections.ArrayList
    $global:DXFakeTaskArgs = ''
    $global:DXFakeReg = @{}
    $global:DXFake64 = $true
    $global:DXCfipOpsOverride = @{
        IsWindows        = { $true }; IsElevated = { $true }; CanPrompt = { $false }
        ProtectPath      = { param($Path, $Directory) [void]$global:DXFake.Add("acl:$Path|$Directory") }
        RegisterTask     = { param($Arguments) [void]$global:DXFake.Add("register:$Arguments") }
        UnregisterTask   = { [void]$global:DXFake.Add('unregister'); $true }
        RunCollector     = { param($Arguments) [void]$global:DXFake.Add("run:$Arguments"); 0 }
        GetTaskArguments = { $global:DXFakeTaskArgs }
        Is64BitOS        = { $global:DXFake64 }
        GetRegDword      = { param($Path, $Name) $global:DXFakeReg["$Path\$Name"] }
        SetRegDword      = { param($Path, $Name, $Value) $global:DXFakeReg["$Path\$Name"] = $Value; [void]$global:DXFake.Add("reg:$Path\$Name=$Value") }
    }
    . (Join-Path $Root 'collector/DXCfip.Install.ps1')
    # The real ProtectPath, kept before the override replaced it, for the SID test.
    $script:RealProtect = ([scriptblock]::Create((Get-Content (Join-Path $Root 'collector/DXCfip.Install.ps1') -Raw))).Ast.FindAll({
            param($a) $a -is [Management.Automation.Language.HashtableAst] }, $true) |
        ForEach-Object { $_.KeyValuePairs } | Where-Object { $_.Item1.Value -eq 'ProtectPath' } |
        Select-Object -First 1 | ForEach-Object { $_.Item2.PipelineElements[0].Expression.ScriptBlock.GetScriptBlock() }

    function script:New-RootPair {
        $base = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        [pscustomobject]@{ New = (Join-Path $base 'Windows/Scripts/DX'); Old = (Join-Path $base 'DX'); Base = $base }
    }
    function script:New-File([string]$Path, [string]$Text) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
        Set-Content -LiteralPath $Path -Value $Text -NoNewline
    }
    function script:Invoke-Install($R, [string]$Token = $Tok, [switch]$FixTls) {
        Invoke-DXCfipInstall -ClientCode acme -ReportUrl 'https://cfip.example.com.au/report' -Token $Token `
            -CollectorContent $CollectorText -RootDir $R.New -LegacyRootDir $R.Old -NoRunNow -FixTls:$FixTls 6>&1 | Out-String
    }
    function script:New-OldInstall($R, [string]$Token = ('Old_' + ('o' * 40))) {
        New-File (Join-Path $R.Old 'Scripts/Invoke-DXCfipCollector.ps1') '# old collector'
        New-File (Join-Path $R.Old 'Config/cfip-collector.json') (@{ ClientCode = 'ACME'; ReportUrl = 'https://old.example/report'; Token = $Token; HeartbeatHours = 6 } | ConvertTo-Json)
        New-File (Join-Path $R.Old 'State/cfip-collector-state.json') '{"Ip":"9.9.9.9","LastReportUtc":"2026-10-01T00:00:00Z"}'
        New-File (Join-Path $R.Old 'Logs/DX-CFIP-Collector.log') "old line`n"
        return $Token
    }
}
AfterAll { Remove-Variable -Scope Global -Name DXCfipOpsOverride, DXFake, DXFakeTaskArgs, DXFakeReg, DXFake64 -ErrorAction SilentlyContinue }
Describe 'DXCfip.Install.ps1' {
BeforeEach { $global:DXFake.Clear(); $global:DXFakeTaskArgs = ''; $global:DXFakeReg = @{}; $global:DXFake64 = $true }

Describe 'Root paths' {
    It 'defaults to <sr>\Scripts\DX and the old root to <sd>\DX' -ForEach @(
        @{ sr = 'C:\Windows'; sd = 'C:'; want = 'C:\Windows\Scripts\DX'; old = 'C:\DX' },
        @{ sr = 'D:\WINNT\'; sd = 'D:'; want = 'D:\WINNT\Scripts\DX'; old = 'D:\DX' },
        @{ sr = ''; sd = ''; want = 'C:\Windows\Scripts\DX'; old = 'C:\DX' }) {
        $keep = $env:SystemRoot, $env:SystemDrive
        try {
            $env:SystemRoot = $sr; $env:SystemDrive = $sd
            Get-DXCfipDefaultRoot | Should -BeExactly $want
            Get-DXCfipLegacyRoot | Should -BeExactly $old
            Resolve-DXCfipRoot '' | Should -BeExactly $want
        }
        finally { $env:SystemRoot, $env:SystemDrive = $keep }
    }
    It 'DX_CFIP_ROOTDIR / -RootDir overrides the default' {
        Resolve-DXCfipRoot '  E:\Tools\DX  ' | Should -BeExactly 'E:\Tools\DX'
        $r = New-RootPair
        Invoke-Install $r | Out-Null
        Test-Path (Join-Path $r.New 'Config/cfip-collector.json') | Should -BeTrue
        ($global:DXFake -match '^register:') | Should -Match ([regex]::Escape((Join-Path $r.New 'Scripts')))
    }
    It 'no install file or folder default still points at C:\DX' {
        foreach ($f in 'install.ps1', 'collector/DXCfip.Install.ps1', 'collector/Install-DXCfipCollector.ps1', 'collector/Invoke-DXCfipCollector.ps1') {
            (Get-Content (Join-Path $Root $f) -Raw) | Should -Not -Match "(RootDir|root)\s*=\s*'C:\\DX'" -Because $f
        }
    }
}

Describe 'ACLs' {
    It 'protects the root, every subfolder and the config file, and creates the missing parent' {
        $r = New-RootPair
        $out = Invoke-Install $r
        Test-Path (Split-Path -Parent $r.New) | Should -BeTrue
        $out | Should -Match 'created .*Scripts'
        foreach ($d in @($r.New) + @('Scripts', 'Config', 'State', 'Logs' | ForEach-Object { Join-Path $r.New $_ })) {
            $global:DXFake | Should -Contain "acl:$d|True"
        }
        $global:DXFake | Should -Contain "acl:$(Join-Path $r.New 'Config/cfip-collector.json')|False"
        # the existing parent (C:\Windows\Scripts) is never re-ACL'd
        $global:DXFake | Should -Not -Contain "acl:$(Split-Path -Parent $r.New)|True"
    }
    It 'real ProtectPath grants FullControl to SIDs S-1-5-18 and S-1-5-32-544 only, inheritance removed (<kind>)' -ForEach @(
        @{ kind = 'directory'; dir = $true; inherit = 'ContainerInherit, ObjectInherit' }, @{ kind = 'file'; dir = $false; inherit = 'None' }) {
        function Get-Acl { param([string]$LiteralPath) $LiteralPath }
        function Set-Acl { param([string]$LiteralPath, $AclObject) $LiteralPath; $AclObject }
        $acl = [pscustomobject]@{ Access = @('inheritedUsersRead', 'trustedInstaller'); Protected = $null; Removed = 0; Added = (New-Object System.Collections.ArrayList) }
        $acl | Add-Member ScriptMethod SetAccessRuleProtection { param($a, $b) $this.Protected = "$a,$b" }
        $acl | Add-Member ScriptMethod RemoveAccessRule { param($x) $null = $x; $this.Removed++; $true }
        $acl | Add-Member ScriptMethod AddAccessRule { param($x) [void]$this.Added.Add($x) }
        Mock Get-Acl { $acl }
        Mock Set-Acl {}
        Mock New-Object -ParameterFilter { $TypeName -like '*SecurityIdentifier' } { [pscustomobject]@{ Sid = $ArgumentList[0] } }
        Mock New-Object -ParameterFilter { $TypeName -like '*FileSystemAccessRule' } {
            [pscustomobject]@{ Id = $ArgumentList[0].Sid; Rights = $ArgumentList[1]; Inherit = [string]$ArgumentList[2]; Type = $ArgumentList[4] } }
        & $RealProtect 'X:\p' $dir
        $acl.Protected | Should -Be 'True,False'
        $acl.Removed | Should -Be 2
        @($acl.Added | ForEach-Object Id) | Should -Be @('S-1-5-18', 'S-1-5-32-544')
        @($acl.Added | ForEach-Object Rights | Select-Object -Unique) | Should -Be 'FullControl'
        @($acl.Added | ForEach-Object Inherit | Select-Object -Unique) | Should -Be $inherit
        Should -Invoke Set-Acl -Times 1 -ParameterFilter { $LiteralPath -eq 'X:\p' }
    }
}

Describe 'Migration from the old C:\DX root' {
    It 'moves config/state/logs, reuses the token, repoints the task, removes only our old files' {
        $r = New-RootPair
        $oldTok = New-OldInstall $r
        New-File (Join-Path $r.Old 'Scripts/Other-Tool.ps1') '# not ours'
        New-File (Join-Path $r.Old 'Logs/other-tool.log') 'not ours'
        $out = Invoke-Install $r -Token ''
        $out | Should -Match 'migration: found'
        $out | Should -Match 'reusing the report token'
        (Get-Content (Join-Path $r.New 'Config/cfip-collector.json') -Raw | ConvertFrom-Json).Token | Should -BeExactly $oldTok
        (Get-Content (Join-Path $r.New 'Config/cfip-collector.json') -Raw | ConvertFrom-Json).ReportUrl | Should -Be 'https://cfip.example.com.au/report'
        Get-Content (Join-Path $r.New 'State/cfip-collector-state.json') -Raw | Should -Match '9\.9\.9\.9'
        Get-Content (Join-Path $r.New 'Logs/DX-CFIP-Collector.log') -Raw | Should -Match 'old line'
        ($global:DXFake -match '^register:') | Should -Match ([regex]::Escape($r.New))
        foreach ($f in 'Scripts/Invoke-DXCfipCollector.ps1', 'Config/cfip-collector.json', 'State/cfip-collector-state.json', 'Logs/DX-CFIP-Collector.log') {
            Test-Path (Join-Path $r.Old $f) | Should -BeFalse -Because $f
        }
        Test-Path (Join-Path $r.Old 'Scripts/Other-Tool.ps1') | Should -BeTrue
        Test-Path (Join-Path $r.Old 'Logs/other-tool.log') | Should -BeTrue
        Test-Path (Join-Path $r.Old 'Config') | Should -BeFalse
        Test-Path (Join-Path $r.Old 'State') | Should -BeFalse
        Test-Path $r.Old | Should -BeTrue
        $out | Should -Match 'kept .*Scripts \(still holds: Other-Tool\.ps1\)'
        $out.Contains($oldTok) | Should -BeFalse
        $out | Should -Match 'migration: done'
    }
    It 'removes the old root entirely when only our files were there' {
        $r = New-RootPair
        New-OldInstall $r | Out-Null
        Invoke-Install $r | Out-Null
        Test-Path $r.Old | Should -BeFalse
    }
    It 'does not overwrite a newer file already at the new root, and merges logs old-first' {
        $r = New-RootPair
        New-OldInstall $r | Out-Null
        (Get-Item (Join-Path $r.Old 'State/cfip-collector-state.json')).LastWriteTimeUtc = (Get-Date).ToUniversalTime().AddDays(-2)
        New-File (Join-Path $r.New 'State/cfip-collector-state.json') '{"Ip":"1.1.1.1","LastReportUtc":"2026-10-29T00:00:00Z"}'
        New-File (Join-Path $r.New 'Logs/DX-CFIP-Collector.log') "new line`n"
        $out = Invoke-Install $r
        Get-Content (Join-Path $r.New 'State/cfip-collector-state.json') -Raw | Should -Match '1\.1\.1\.1'
        $out | Should -Match 'kept the newer'
        (Get-Content (Join-Path $r.New 'Logs/DX-CFIP-Collector.log') -Raw) | Should -Match '(?s)old line.*new line'
        Test-Path (Join-Path $r.Old 'State/cfip-collector-state.json') | Should -BeFalse
    }
    It 'replaces an older file at the new root with the newer old one' {
        $r = New-RootPair
        New-OldInstall $r | Out-Null
        New-File (Join-Path $r.New 'State/cfip-collector-state.json') '{"Ip":"1.1.1.1"}'
        (Get-Item (Join-Path $r.New 'State/cfip-collector-state.json')).LastWriteTimeUtc = (Get-Date).ToUniversalTime().AddDays(-5)
        (Invoke-Install $r) | Should -Match 'is newer, replaced'
        Get-Content (Join-Path $r.New 'State/cfip-collector-state.json') -Raw | Should -Match '9\.9\.9\.9'
    }
    It 'detects an old install from the scheduled task alone' {
        $r = New-RootPair
        $global:DXFakeTaskArgs = "powershell.exe -File `"$(Join-Path $r.Old 'Scripts/Invoke-DXCfipCollector.ps1')`""
        $out = Invoke-Install $r
        $out | Should -Match 'scheduled task points at the old root'
        $out | Should -Match 'clean reinstall'
        ($global:DXFake -match '^register:') | Should -Match ([regex]::Escape($r.New))
    }
    It 'does nothing extra when there is no old install, or the root IS the old root' {
        $r = New-RootPair
        (Invoke-Install $r) | Should -Not -Match 'migration'
        $same = [pscustomobject]@{ New = $r.Old; Old = $r.Old }
        New-OldInstall $same | Out-Null
        (Invoke-Install $same) | Should -Not -Match 'migration'
        Test-Path (Join-Path $r.Old 'Config/cfip-collector.json') | Should -BeTrue
    }
    It 'keeps the old install working when the new install fails before the task is repointed' {
        $r = New-RootPair
        New-OldInstall $r | Out-Null
        $keep = $DXCfipOps.RegisterTask
        $DXCfipOps.RegisterTask = { throw 'task scheduler unavailable' }
        try { $out = Invoke-Install $r } finally { $DXCfipOps.RegisterTask = $keep }
        $out | Should -Match 'install failed'
        Test-Path (Join-Path $r.Old 'Config/cfip-collector.json') | Should -BeTrue
        Test-Path (Join-Path $r.Old 'Scripts/Invoke-DXCfipCollector.ps1') | Should -BeTrue
    }
}

Describe 'Uninstall' {
    It 'cleans our files from the new and the old root, keeps logs and unknown files, removes empty folders' {
        $r = New-RootPair
        Invoke-Install $r | Out-Null
        New-File (Join-Path $r.New 'State/cfip-collector-state.json') '{}'
        New-File (Join-Path $r.New 'Logs/DX-CFIP-Collector.log') 'x'
        New-OldInstall $r | Out-Null
        New-File (Join-Path $r.Old 'Config/someone-else.json') '{}'
        $out = Invoke-DXCfipUninstall -RootDir $r.New -LegacyRootDir $r.Old 6>&1 | Out-String
        $global:DXFake | Should -Contain 'unregister'
        foreach ($root in $r.New, $r.Old) {
            foreach ($f in 'Scripts/Invoke-DXCfipCollector.ps1', 'Config/cfip-collector.json', 'State/cfip-collector-state.json') {
                Test-Path (Join-Path $root $f) | Should -BeFalse -Because "$root $f"
            }
            Test-Path (Join-Path $root 'Scripts') | Should -BeFalse
            Test-Path (Join-Path $root 'State') | Should -BeFalse
            Test-Path (Join-Path $root 'Logs/DX-CFIP-Collector.log') | Should -BeTrue
        }
        Test-Path (Join-Path $r.New 'Config') | Should -BeFalse
        Test-Path (Join-Path $r.Old 'Config/someone-else.json') | Should -BeTrue
        $out | Should -Match 'logs kept'
    }
    It 'removes both roots completely when nothing but empty folders are left' {
        $r = New-RootPair
        Invoke-Install $r | Out-Null
        New-Item -ItemType Directory (Join-Path $r.Old 'Config') -Force | Out-Null
        New-File (Join-Path $r.Old 'Config/cfip-collector.json') '{}'
        Invoke-DXCfipUninstall -RootDir $r.New -LegacyRootDir $r.Old 6>&1 | Out-Null
        Test-Path $r.Old | Should -BeFalse
        Test-Path $r.New | Should -BeFalse
    }
}

Describe 'DX_CFIP_FIXTLS (.NET strong crypto registry values)' {
    BeforeAll {
        $script:K64 = 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319'
        $script:K32 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319'
    }
    It 'off (default): no registry writes, warns about the missing values' {
        $out = Invoke-DXCfipTlsCheck 6>&1 | Out-String
        @($global:DXFake -match '^reg:').Count | Should -Be 0
        $out | Should -Match 'DX_CFIP_FIXTLS=1'
        $out | Should -Match 'SchUseStrongCrypto \(missing\)'
    }
    It 'off and already set: no writes, no warning' {
        foreach ($k in $K64, $K32) { foreach ($n in 'SchUseStrongCrypto', 'SystemDefaultTlsVersions') { $global:DXFakeReg["$k\$n"] = 1 } }
        (Invoke-DXCfipTlsCheck 6>&1 | Out-String) | Should -Not -Match 'TLS:'
        @($global:DXFake -match '^reg:').Count | Should -Be 0
    }
    It 'on: writes only the values that are missing or not 1, on both paths, and notes a new process is needed' {
        $global:DXFakeReg["$K64\SchUseStrongCrypto"] = 1
        $global:DXFakeReg["$K32\SystemDefaultTlsVersions"] = 0
        $out = Invoke-DXCfipTlsCheck -Fix 6>&1 | Out-String
        $w = @($global:DXFake -match '^reg:')
        $w.Count | Should -Be 3
        $w | Should -Contain "reg:$K64\SystemDefaultTlsVersions=1"
        $w | Should -Contain "reg:$K32\SchUseStrongCrypto=1"
        $w | Should -Contain "reg:$K32\SystemDefaultTlsVersions=1"
        $out | Should -Match 'was 0'
        $out | Should -Match 'missing'
        $out | Should -Match 'New processes'
        $out | Should -Match 'reboot'
    }
    It 'on, 32-bit Windows: only the native key' {
        $global:DXFake64 = $false
        Invoke-DXCfipTlsCheck -Fix 6>&1 | Out-Null
        @($global:DXFake -match '^reg:').Count | Should -Be 2
        @($global:DXFake -match 'WOW6432Node').Count | Should -Be 0
    }
    It 'install passes -FixTls through (and does not write without it)' {
        Invoke-Install (New-RootPair) | Out-Null
        @($global:DXFake -match '^reg:').Count | Should -Be 0
        Invoke-Install (New-RootPair) -FixTls | Out-Null
        @($global:DXFake -match '^reg:').Count | Should -Be 4
    }
}
}

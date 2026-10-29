<#
Build-Bundle.ps1 - makes dist/Install-DXCfipCollector.bundle.ps1: the N-central installer with the shared
install code (DXCfip.Install.ps1) and the collector embedded, so N-central needs ONE script file.
Re-run after changing any of the three. Exit codes: 0 = built, 1 = error.
#>
[CmdletBinding()]
param([string]$OutDir = '')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }
$installer = Get-Content -LiteralPath (Join-Path $root 'collector/Install-DXCfipCollector.ps1') -Raw
$embeds = [ordered]@{
    "    `$EmbeddedLib = ''"       = 'collector/DXCfip.Install.ps1'
    "    `$EmbeddedCollector = ''" = 'collector/Invoke-DXCfipCollector.ps1'
}
foreach ($marker in $embeds.Keys) {
    $content = Get-Content -LiteralPath (Join-Path $root $embeds[$marker]) -Raw
    if ($content -match "(?m)^'@") { Write-Error "$($embeds[$marker]) has a line starting with '@ and cannot be embedded"; exit 1 }
    if (-not $installer.Contains($marker)) { Write-Error "embed marker not found: $marker"; exit 1 }
    $installer = $installer.Replace($marker, $marker.Replace("''", "@'`n" + $content.TrimEnd() + "`n'@"))
}
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$dest = Join-Path $OutDir 'Install-DXCfipCollector.bundle.ps1'
[IO.File]::WriteAllText($dest, $installer, (New-Object Text.UTF8Encoding($true)))  # BOM: PS 5.1 reads UTF-8 correctly
$errs = $null
[void][Management.Automation.Language.Parser]::ParseFile($dest, [ref]$null, [ref]$errs)
if ($errs) { Write-Error "bundle does not parse: $($errs[0].Message)"; exit 1 }
Write-Output "built $dest"
exit 0

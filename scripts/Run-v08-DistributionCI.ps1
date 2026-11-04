#requires -Version 5.1
<#
BOMB SQUAD v0.8 / Slice 4 - distribution CI orchestrator.
Uses the existing self-contained publish, ZIP bundler and per-file verifier.
Runs locally for diagnostics or on the hosted Windows Actions runner.
Never executes inspected PowerShell source, signs binaries, or creates a release.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Windows is required to build this WinUI distribution.'
}
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ([System.IO.Path]::GetFullPath((Get-Location).Path) -ne [System.IO.Path]::GetFullPath($repo)) {
    throw 'Run from the BOMB SQUAD repository root.'
}

$publishScript = Join-Path $PSScriptRoot 'Publish-v08-UnpackagedProbe.ps1'
$bundleScript = Join-Path $PSScriptRoot 'Build-v08-DistributionZip.ps1'
$verifyScript = Join-Path $PSScriptRoot 'Verify-v08-DistributionZip.ps1'
foreach ($path in @($publishScript, $bundleScript, $verifyScript)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required v0.8 script not found: $path"
    }
}

# Capture the initial directories so an older, successful probe is never
# accidentally uploaded instead of the result from this execution.
$temp = [System.IO.Path]::GetTempPath()
$beforePublish = @(Get-ChildItem -LiteralPath $temp -Directory -Filter 'BombSquad-v08-PublishProbe-*' | ForEach-Object { $_.FullName })
$beforeBundle = @(Get-ChildItem -LiteralPath $temp -Directory -Filter 'BombSquad-v08-ZipProbe-*' | ForEach-Object { $_.FullName })

Write-Host "`n=== PUBLISH SELF-CONTAINED WINDOWS APPLICATION ===" -ForegroundColor Cyan
& $publishScript
# The called script throws if dotnet publish fails.

$newPublish = @(Get-ChildItem -LiteralPath $temp -Directory -Filter 'BombSquad-v08-PublishProbe-*' |
    Where-Object { $beforePublish -notcontains $_.FullName })
if ($newPublish.Count -ne 1) {
    throw "Expected exactly one NEW publish directory; found $($newPublish.Count)."
}
$publish = Join-Path $newPublish[0].FullName 'publish'
$summary = Join-Path $newPublish[0].FullName 'publish-probe-summary.txt'
if (-not (Test-Path -LiteralPath $summary -PathType Leaf)) {
    throw 'Publish summary missing from this run.'
}

Write-Host "`n=== CREATE PREVIEW ZIP AND INTEGRITY MANIFEST ===" -ForegroundColor Cyan
& $bundleScript -PublishDirectory $publish

$newBundles = @(Get-ChildItem -LiteralPath $temp -Directory -Filter 'BombSquad-v08-ZipProbe-*' |
    Where-Object { $beforeBundle -notcontains $_.FullName })
if ($newBundles.Count -ne 1) {
    throw "Expected exactly one NEW distribution bundle; found $($newBundles.Count)."
}
$bundle = $newBundles[0].FullName

Write-Host "`n=== EXTRACT AND VERIFY DISTRIBUTION ===" -ForegroundColor Cyan
& $verifyScript -BundleDirectory $bundle

$baseName = 'BOMB-SQUAD-v0.8-preview-win-x64'
$expected = @(
    ($baseName + '.zip')
    ($baseName + '.manifest.json')
    'SHA256SUMS.txt'
)
foreach ($name in $expected) {
    $path = Join-Path $bundle $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required CI artifact missing: $name"
    }
}
$actual = @(Get-ChildItem -LiteralPath $bundle -File | Select-Object -ExpandProperty Name)
if (@(Compare-Object $expected $actual).Count -ne 0) {
    throw 'Bundle has missing or unexpected root files. Refusing upload.'
}

$manifestPath = Join-Path $bundle ($baseName + '.manifest.json')
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$head = (& git rev-parse HEAD)
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($head)) {
    throw 'Cannot resolve current Git commit.'
}
if ([string]$manifest.sourceCommit -ne $head.Trim()) {
    throw 'Manifest commit does not match checked-out source.'
}
if ($manifest.cleanMachineVerified -ne $false -or $manifest.publicRelease -ne $false) {
    throw 'Preview manifest must not claim release or clean-machine verification.'
}
if ([int]$manifest.publishFileCount -lt 100) {
    throw 'Distribution manifest reports too few files.'
}

# Make the new folder discoverable by actions/upload-artifact. No file from
# the Git working tree is staged, committed, uploaded as a release, or signed.
if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_OUTPUT)) {
    $outputLine = "artifact_dir=$bundle" + "`n"
    [System.IO.File]::AppendAllText(
        $env:GITHUB_OUTPUT, $outputLine, [System.Text.UTF8Encoding]::new($false)
    )
}

Write-Host "`nPASS: v0.8 DISTRIBUTION CI PIPELINE VERIFIED." -ForegroundColor Green
Write-Host "Commit: $($head.Trim())"
Write-Host "Files in ZIP manifest: $($manifest.publishFileCount)"
Write-Host "CI artifact directory: $bundle"
Write-Host 'Preview only. Windows application launch and clean-machine setup need separate manual QA.'

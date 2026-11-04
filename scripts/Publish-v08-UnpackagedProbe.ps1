#requires -Version 5.1
<#
BOMB SQUAD v0.8 / Slice 1
Non-destructive, local Windows x64 UNPACKAGED publish probe.
Uses Microsoft-documented WindowsPackageType=None and WindowsAppSDKSelfContained=true.
Does not run inspected PowerShell source or install/register an application.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This probe must run on Windows.'
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$project = Join-Path $repoRoot 'src\BombSquad.Desktop\BombSquad.Desktop.csproj'
if (-not (Test-Path -LiteralPath $project -PathType Leaf)) {
    throw 'Desktop project not found relative to scripts directory.'
}

# A unique temp directory prevents overwriting user files and keeps publish output
# outside the Git working tree. Retain output for manual review and clean-machine QA.
$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'BombSquad-v08-PublishProbe-' + [guid]::NewGuid().ToString('N')
)
$publishDir = Join-Path $probeRoot 'publish'
New-Item -ItemType Directory -Path $publishDir -Force | Out-Null

Write-Host "`nBOMB SQUAD v0.8 - unpackaged x64 publish probe" -ForegroundColor Cyan
Write-Host 'Scope: local Release publish only; NOT a verified installer or public release.'
Write-Host "Source project: $project"
Write-Host "Publish output: $publishDir"
Write-Host 'Configuration: Release / win-x64 / .NET + Windows App SDK self-contained'
Write-Host 'No MSIX, no signing, no trimming, no single-file extraction.'

# Explicit command-line MSBuild properties override the existing Release defaults.
# Do not remove any DLL from the resulting directory; it is a multi-file deployment.
& dotnet publish $project `
    --configuration Release `
    --runtime win-x64 `
    --self-contained true `
    --output $publishDir `
    '-p:WindowsPackageType=None' `
    '-p:WindowsAppSDKSelfContained=true' `
    '-p:PublishTrimmed=false' `
    '-p:PublishReadyToRun=false' `
    '-p:PublishSingleFile=false' `
    '-p:GenerateAppxPackageOnBuild=false'

if ($LASTEXITCODE -ne 0) {
    throw "Publish failed (exit code $LASTEXITCODE). Do not commit or distribute. Share the full error output. Probe directory: $probeRoot"
}

$exe = Join-Path $publishDir 'BombSquad.Desktop.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw "Publish returned success, but the expected EXE was missing: $exe"
}

$exeInfo = Get-Item -LiteralPath $exe
if ($exeInfo.Length -le 0) {
    throw 'Published EXE has zero size. Stop.'
}
# Brand assets must exist on disk for the unpackaged XAML header and AppWindow icon.
$requiredAssets = @(
    'Assets\AppIcon.ico',
    'Assets\Square44x44Logo.png',
    'Assets\Square44x44Logo.scale-200.png'
)
foreach ($asset in $requiredAssets) {
    $sourceAsset = Join-Path (Split-Path -Parent $project) $asset
    $publishedAsset = Join-Path $publishDir $asset
    if (-not (Test-Path -LiteralPath $publishedAsset -PathType Leaf)) {
        throw "Publish is missing required branding asset: $publishedAsset. Not distribution-ready."
    }
    $sourceHash = (Get-FileHash -LiteralPath $sourceAsset -Algorithm SHA256).Hash
    $publishedHash = (Get-FileHash -LiteralPath $publishedAsset -Algorithm SHA256).Hash
    if ($sourceHash -ne $publishedHash) {
        throw "Published branding asset differs from source: $asset. Stop."
    }
}
Write-Host 'PASS: All required physical branding assets were published.' -ForegroundColor Green

$files = @(Get-ChildItem -LiteralPath $publishDir -Recurse -File)
if ($files.Count -lt 2) {
    throw 'Publish output contains too few files for a normal self-contained folder build.'
}

[long]$totalBytes = 0
foreach ($file in $files) { $totalBytes += $file.Length }

# Inventory resolved dependency versions for the next (pinning) slice.
# This is an auxiliary diagnostic: publishing is still the primary gate.
$inventoryPath = Join-Path $probeRoot 'resolved-nuget-packages.txt'
try {
    $packageInfo = & dotnet list $project package --include-transitive 2>&1
    $inventoryExit = $LASTEXITCODE
    $packageInfo | Out-File -LiteralPath $inventoryPath -Encoding UTF8
    if ($inventoryExit -ne 0) {
        Write-Warning 'NuGet package inventory command failed. Inspect the inventory text.'
    }
}
catch {
    Write-Warning "NuGet package inventory was unavailable: $($_.Exception.Message)"
}

$metadataPath = Join-Path $probeRoot 'publish-probe-summary.txt'
$summary = @(
    'BOMB SQUAD - v0.8 LOCAL UNPACKAGED PUBLISH PROBE',
    'This is not a signed or clean-machine-verified release.',
    'Target: win-x64',
    'Configuration: Release',
    'WindowsPackageType: None',
    'WindowsAppSDKSelfContained: true',
    'DotNetSelfContained: true',
    'PublishTrimmed: false',
    'PublishReadyToRun: false',
    'PublishSingleFile: false',
    "PublishFolder: $publishDir",
    "Executable: $exe",
    "FileCount: $($files.Count)",
    "TotalBytes: $totalBytes",
    "NuGetInventory: $inventoryPath"
) -join [Environment]::NewLine
[System.IO.File]::WriteAllText($metadataPath, $summary, [System.Text.UTF8Encoding]::new($false))

Write-Host "`nPASS: LOCAL PUBLISH PROBE COMPLETED." -ForegroundColor Green
Write-Host "Published EXE: $exe"
Write-Host "Files: $($files.Count)"
Write-Host ('Total size: {0:N1} MiB' -f ($totalBytes / 1MB))
Write-Host "Package inventory: $inventoryPath"
Write-Host "Probe summary: $metadataPath"
Write-Host 'NEXT: Open this EXE directly from the publish folder, not via dotnet run.'
Write-Host 'Do not zip/share/publish the output until launch and clean-machine checks pass.'

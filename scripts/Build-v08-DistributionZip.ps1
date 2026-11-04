#requires -Version 5.1
<#
BOMB SQUAD v0.8 / Slice 3 - Local preview distribution bundle.
Takes a successful UNPACKAGED publish probe folder and creates a portable ZIP,
a per-file SHA-256 manifest, and SHA256SUMS.txt. No source is executed.
No GitHub Release is created. No source files are modified.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PublishDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Distribution bundling requires Windows.'
}

$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ((Get-Location).Path -ne $repo) {
    throw 'Run this script from the BOMB SQUAD repository root.'
}
$branch = (& git branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or $branch -ne 'feat/v08-windows-distribution') {
    throw 'Expected feat/v08-windows-distribution. Stop.'
}
& git merge-base --is-ancestor 6d01422 HEAD
if ($LASTEXITCODE -ne 0) {
    throw 'Current branch does not contain verified Slice 2 commit 6d01422. Stop.'
}
$commit = (& git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($commit)) {
    throw 'Cannot determine Git source commit. Stop.'
}

$publish = (Resolve-Path -LiteralPath $PublishDirectory).Path.TrimEnd([char]'\')
$probeRoot = Split-Path -Parent $publish
if ((Split-Path -Leaf $publish) -ne 'publish' -or
    (Split-Path -Leaf $probeRoot) -notlike 'BombSquad-v08-PublishProbe-*') {
    throw 'Use the publish folder inside a BOMB SQUAD v0.8 PublishProbe directory.'
}
$summaryPath = Join-Path $probeRoot 'publish-probe-summary.txt'
if (-not (Test-Path -LiteralPath $summaryPath -PathType Leaf)) {
    throw 'Missing successful publish-probe summary. Stop.'
}
$summary = [System.IO.File]::ReadAllText($summaryPath)
foreach ($entry in @(
    "PublishFolder: $publish",
    'WindowsPackageType: None',
    'WindowsAppSDKSelfContained: true',
    'DotNetSelfContained: true',
    'PublishTrimmed: false',
    'PublishSingleFile: false'
)) {
    if ($summary.IndexOf($entry, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "Publish probe metadata is missing: $entry"
    }
}

foreach ($relative in @(
    'BombSquad.Desktop.exe',
    'Assets\AppIcon.ico',
    'Assets\Square44x44Logo.png',
    'Assets\Square44x44Logo.scale-200.png'
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $publish $relative) -PathType Leaf)) {
        throw "Publish output is missing: $relative"
    }
}

$links = @(Get-ChildItem -LiteralPath $publish -Recurse -Force |
    Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 })
if ($links.Count -gt 0) {
    throw 'Publish output contains reparse points. Review the files before packaging.'
}

$files = @(Get-ChildItem -LiteralPath $publish -Recurse -File -Force |
    Sort-Object FullName)
if ($files.Count -lt 100) {
    throw "Only $($files.Count) published files found. Expected a full self-contained distribution."
}

$prefix = $publish + '\'
$entries = New-Object 'System.Collections.Generic.List[object]'
[long]$totalBytes = 0
foreach ($file in $files) {
    if (-not $file.FullName.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unexpected file outside publish directory.'
    }
    $relative = $file.FullName.Substring($prefix.Length).Replace('\', '/')
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    [void]$entries.Add([ordered]@{
        path = $relative
        sizeBytes = [long]$file.Length
        sha256 = $hash
    })
    $totalBytes += $file.Length
}

$bundle = Join-Path ([System.IO.Path]::GetTempPath()) (
    'BombSquad-v08-ZipProbe-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $bundle -Force | Out-Null
$baseName = 'BOMB-SQUAD-v0.8-preview-win-x64'
$zipName = $baseName + '.zip'
$manifestName = $baseName + '.manifest.json'
$zipPath = Join-Path $bundle $zipName
$manifestPath = Join-Path $bundle $manifestName
$checksumsPath = Join-Path $bundle 'SHA256SUMS.txt'

Write-Host "`n=== CREATE WINDOWS ZIP ===" -ForegroundColor Cyan
Write-Host "Source publish folder: $publish"
Write-Host "Preview output folder: $bundle"
Write-Host "Published files: $($files.Count)"
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $publish,
    $zipPath,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $false
)
if (-not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
    throw 'ZIP creation did not produce an archive.'
}

$zipInfo = Get-Item -LiteralPath $zipPath
$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [ordered]@{
    schemaVersion = '1.0'
    product = 'BOMB SQUAD'
    version = '0.8.0-preview'
    target = 'win-x64'
    distribution = 'unpackaged-self-contained'
    publicRelease = $false
    cleanMachineVerified = $false
    sourceCommit = $commit
    createdUtc = [DateTime]::UtcNow.ToString('o')
    publishFileCount = $files.Count
    publishTotalBytes = $totalBytes
    archive = [ordered]@{
        fileName = $zipName
        sizeBytes = [long]$zipInfo.Length
        sha256 = $zipHash
    }
    files = $entries.ToArray()
    limitations = @(
        'Unsigned local preview only; not a GitHub Release or installer.',
        'Clean-machine installation and launch have not been verified.',
        'The complete ZIP must be extracted; do not run the EXE from inside the ZIP.',
        'SHA-256 verifies integrity against this manifest, not publisher identity.'
    )
}
$json = ConvertTo-Json -InputObject $manifest -Depth 8
[System.IO.File]::WriteAllText(
    $manifestPath, $json + "`r`n", [System.Text.UTF8Encoding]::new($false)
)
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$lines = @(
    "$zipHash *$zipName",
    "$manifestHash *$manifestName"
)
[System.IO.File]::WriteAllText(
    $checksumsPath, (($lines -join "`r`n") + "`r`n"),
    [System.Text.UTF8Encoding]::new($false)
)

Write-Host "`nPASS: PREVIEW DISTRIBUTION BUNDLE CREATED." -ForegroundColor Green
Write-Host "Bundle directory: $bundle"
Write-Host "ZIP: $zipPath"
Write-Host "Manifest: $manifestPath"
Write-Host "Checksums: $checksumsPath"
Write-Host "ZIP SHA-256: $zipHash"
Write-Host ('Uncompressed: {0:N1} MiB' -f ($totalBytes / 1MB))
Write-Host ('ZIP size: {0:N1} MiB' -f ($zipInfo.Length / 1MB))
Write-Host 'NEXT: Run Verify-v08-DistributionZip.ps1 against this bundle.'
Write-Host 'Do not upload or publish this preview as a release yet.'

#requires -Version 5.1
<#
BOMB SQUAD v0.8 / Slice 3 - Verify a locally built preview ZIP.
Checks SHA256SUMS, validates the manifest, extracts to a NEW temp folder,
then verifies every extracted file against its SHA-256 and length.
Does not execute the published app or any PowerShell being analyzed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BundleDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'Distribution verification requires Windows.'
}

$bundle = (Resolve-Path -LiteralPath $BundleDirectory).Path
$baseName = 'BOMB-SQUAD-v0.8-preview-win-x64'
$zipName = $baseName + '.zip'
$manifestName = $baseName + '.manifest.json'
$zipPath = Join-Path $bundle $zipName
$manifestPath = Join-Path $bundle $manifestName
$checksumsPath = Join-Path $bundle 'SHA256SUMS.txt'
foreach ($path in @($zipPath, $manifestPath, $checksumsPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing distribution file: $path"
    }
}

$zipHash = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumLines = @(Get-Content -LiteralPath $checksumsPath |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
foreach ($required in @(
    "$zipHash *$zipName",
    "$manifestHash *$manifestName"
)) {
    if ($checksumLines -notcontains $required) {
        throw "SHA256SUMS.txt verification failed: $required"
    }
}
if ($checksumLines.Count -ne 2) {
    throw 'Expected exactly two checksum entries.'
}

try { $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json }
catch { throw "Cannot parse distribution manifest: $($_.Exception.Message)" }
if ($manifest.schemaVersion -ne '1.0' -or
    $manifest.version -ne '0.8.0-preview' -or
    $manifest.target -ne 'win-x64' -or
    $manifest.distribution -ne 'unpackaged-self-contained' -or
    $manifest.publicRelease -ne $false -or
    $manifest.cleanMachineVerified -ne $false -or
    $manifest.archive.fileName -ne $zipName -or
    $manifest.archive.sha256 -ne $zipHash -or
    [long]$manifest.archive.sizeBytes -ne (Get-Item -LiteralPath $zipPath).Length) {
    throw 'Distribution manifest metadata does not match the local preview archive.'
}
$expectedFiles = @($manifest.files)
if ($expectedFiles.Count -lt 100 -or
    $expectedFiles.Count -ne [int]$manifest.publishFileCount) {
    throw 'Distribution manifest file count is inconsistent.'
}

# Reject ambiguous or undeclared ZIP entries BEFORE the existing extraction and hash checks.
$entryPreflight = Join-Path $PSScriptRoot 'Test-v09-ArchiveEntryPreflight.ps1'
if (-not (Test-Path -LiteralPath $entryPreflight -PathType Leaf)) {
    throw 'v0.9 ZIP entry preflight missing. Refusing extraction.'
}
& $entryPreflight -ZipPath $zipPath -ManifestPath $manifestPath

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    foreach ($entry in $archive.Entries) {
        $name = $entry.FullName.Replace('\', '/')
        if ($name.StartsWith('/') -or $name.Contains(':') -or
            $name -match '(^|/)\.\.(/|$)') {
            throw "Unsafe ZIP entry path: $name"
        }
    }
}
finally {
    $archive.Dispose()
}

$extract = Join-Path ([System.IO.Path]::GetTempPath()) (
    'BombSquad-v08-ZipVerify-' + [guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $extract -Force | Out-Null
Write-Host "`n=== EXTRACT AND VERIFY ZIP ===" -ForegroundColor Cyan
Write-Host "Archive: $zipPath"
Write-Host "Extraction: $extract"
[System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extract)
$actualFiles = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Force)
if ($actualFiles.Count -ne $expectedFiles.Count) {
    throw "Extracted count $($actualFiles.Count) differs from manifest count $($expectedFiles.Count)."
}

$seen = @{}
[long]$bytes = 0
$prefix = $extract.TrimEnd([char]'\') + '\'
foreach ($item in $expectedFiles) {
    $relative = [string]$item.path
    if ([string]::IsNullOrWhiteSpace($relative) -or
        $relative.StartsWith('/') -or $relative.Contains(':') -or
        $relative.Contains('\') -or $relative -match '(^|/)\.\.(/|$)') {
        throw "Unsafe manifest path: $relative"
    }
    if ($seen.ContainsKey($relative)) {
        throw "Duplicate manifest path: $relative"
    }
    $seen[$relative] = $true
    $filePath = Join-Path $extract ($relative.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        throw "File from manifest missing after extraction: $relative"
    }
    $info = Get-Item -LiteralPath $filePath
    if ([long]$info.Length -ne [long]$item.sizeBytes) {
        throw "Size mismatch: $relative"
    }
    $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne [string]$item.sha256) {
        throw "SHA-256 mismatch: $relative"
    }
    $bytes += $info.Length
}
foreach ($actual in $actualFiles) {
    if (-not $actual.FullName.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Unexpected extracted file location.'
    }
    $relative = $actual.FullName.Substring($prefix.Length).Replace('\', '/')
    if (-not $seen.ContainsKey($relative)) {
        throw "Unexpected file not present in manifest: $relative"
    }
}
if ($bytes -ne [long]$manifest.publishTotalBytes) {
    throw 'Extracted total bytes do not match manifest.'
}
$exe = Join-Path $extract 'BombSquad.Desktop.exe'
foreach ($relative in @(
    'Assets\AppIcon.ico',
    'Assets\Square44x44Logo.png',
    'Assets\Square44x44Logo.scale-200.png'
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $extract $relative) -PathType Leaf)) {
        throw "Branding asset missing after ZIP extraction: $relative"
    }
}
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw 'Extracted desktop EXE is missing.'
}

Write-Host "`nPASS: ZIP INTEGRITY AND ALL $($expectedFiles.Count) FILE HASHES VERIFIED." -ForegroundColor Green
Write-Host "ZIP SHA-256: $zipHash"
Write-Host "Extracted folder: $extract"
Write-Host "Extracted EXE: $exe"
Write-Host 'NEXT: Launch the extracted EXE manually and inspect the sample.'
Write-Host 'NOT clean-machine-verified, signed, or publicly released.'

#requires -Version 5.1
<#
BOMB SQUAD v0.9 / Slice 2 - check ZIP central-directory entries BEFORE extraction.
This is a structural safety check, not publisher authentication or malware analysis.
Read-only: does not extract, run or modify the archive or inspected PowerShell.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ZipPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ManifestPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$zip = (Resolve-Path -LiteralPath $ZipPath -ErrorAction Stop).Path
$manifestFile = (Resolve-Path -LiteralPath $ManifestPath -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $zip -PathType Leaf) -or
    -not (Test-Path -LiteralPath $manifestFile -PathType Leaf)) {
    throw 'ZIP and manifest must be existing files.'
}

try {
    $manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
}
catch {
    throw "Invalid release manifest JSON: $($_.Exception.Message)"
}

$expected = @{}
$expectedNames = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
[long]$declaredTotal = 0
foreach ($item in @($manifest.files)) {
    if ($null -eq $item) { throw 'Null file entry in manifest.' }
    $name = [string]$item.path
    if ([string]::IsNullOrWhiteSpace($name)) {
        throw 'Manifest contains an empty file path.'
    }
    if (-not $expectedNames.Add($name)) {
        throw "Duplicate or case-colliding manifest file: $name"
    }
    if ([string]$item.sha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw "Manifest file hash is not a lowercase SHA-256: $name"
    }
    [long]$length = $item.sizeBytes
    if ($length -lt 0) { throw "Negative manifest size: $name" }
    $expected[$name] = $item
    $declaredTotal += $length
}
if ($expectedNames.Count -eq 0 -or
    $expectedNames.Count -ne [int]$manifest.publishFileCount -or
    $declaredTotal -ne [long]$manifest.publishTotalBytes) {
    throw 'Manifest file count or total size is inconsistent.'
}

function Assert-SafeEntryName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name) -or
        $Name.StartsWith('/') -or $Name.Contains('\') -or
        $Name.Contains(':') -or $Name.Contains([char]0)) {
        throw "Unsafe archive or manifest path: $Name"
    }
    $trimmed = $Name.TrimEnd('/')
    if ($trimmed.Length -eq 0) { throw 'Archive path is empty.' }
    foreach ($segment in $trimmed.Split([char]'/')) {
        if ($segment.Length -eq 0 -or $segment -eq '.' -or $segment -eq '..' -or
            $segment.EndsWith('.') -or $segment.EndsWith(' ') -or
            $segment -match '[<>"|?*]' -or
            $segment -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$') {
            throw "Unsafe or Windows-ambiguous archive path: $Name"
        }
    }
}
foreach ($name in $expectedNames) {
    Assert-SafeEntryName -Name $name
    if ($name.EndsWith('/')) {
        throw "Manifest must name a file, not a directory: $name"
    }
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
try {
    $seenFiles = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    [long]$archiveTotal = 0
    foreach ($entry in $archive.Entries) {
        $name = [string]$entry.FullName
        Assert-SafeEntryName -Name $name
        $isDirectory = $name.EndsWith('/')
        $normalized = if ($isDirectory) { $name.TrimEnd('/') } else { $name }
        if (-not $seenPaths.Add($normalized)) {
            throw "Duplicate or case-colliding ZIP entry: $name"
        }
        # Unix symlinks cannot be packaged as ordinary files or directories.
        $unixType = ($entry.ExternalAttributes -shr 16) -band 0xF000
        if ($unixType -eq 0xA000) { throw "ZIP contains a symbolic link: $name" }
        if ($isDirectory) {
            if ($entry.Length -ne 0) {
                throw "ZIP directory entry contains data: $name"
            }
            continue
        }
        if (-not $expectedNames.Contains($name)) {
            throw "Unexpected ZIP file absent from manifest: $name"
        }
        if (-not $seenFiles.Add($name)) {
            throw "Duplicate ZIP file: $name"
        }
        $reference = $expected[$name]
        if ($name -cne [string]$reference.path) {
            throw "ZIP path case differs from manifest: $name"
        }
        if ([long]$entry.Length -ne [long]$reference.sizeBytes) {
            throw "ZIP entry size differs from manifest: $name"
        }
        $archiveTotal += [long]$entry.Length
    }
    if ($seenFiles.Count -ne $expectedNames.Count -or
        $archiveTotal -ne $declaredTotal) {
        throw 'ZIP file count or total length differs from manifest before extraction.'
    }
}
finally {
    $archive.Dispose()
}
Write-Host "PASS: ZIP entry preflight ($($expectedNames.Count) files; no unsafe, duplicate or undeclared entries)." -ForegroundColor Green
Write-Host 'Next stage verifies actual extracted SHA-256 values against the manifest.'

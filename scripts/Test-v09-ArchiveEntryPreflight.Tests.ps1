#requires -Version 5.1
<#
BOMB SQUAD v0.9 / Slice 2 - deterministic ZIP preflight regression scenarios.
Only creates synthetic text fixtures and archives in a unique temporary folder.
No application binaries or untrusted PowerShell scripts are executed.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$validator = Join-Path $PSScriptRoot 'Test-v09-ArchiveEntryPreflight.ps1'
if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
    throw 'ZIP preflight helper missing.'
}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$root = Join-Path ([System.IO.Path]::GetTempPath()) (
    'BombSquad-v09-ArchiveTests-' + [guid]::NewGuid().ToString('N')
)
$source = Join-Path $root 'source'
New-Item -ItemType Directory -Path $source -Force | Out-Null

function Add-ZipEntry {
    param([string]$ArchivePath, [string]$EntryName)
    $archive = [System.IO.Compression.ZipFile]::Open(
        $ArchivePath, [System.IO.Compression.ZipArchiveMode]::Update
    )
    try {
        $entry = $archive.CreateEntry($EntryName)
        $writer = [System.IO.StreamWriter]::new($entry.Open())
        try { $writer.Write('synthetic') }
        finally { $writer.Dispose() }
    }
    finally { $archive.Dispose() }
}

function Assert-Blocked {
    param([string]$Label, [string]$ArchivePath, [string]$ManifestPath)
    $blocked = $false
    try { & $validator -ZipPath $ArchivePath -ManifestPath $ManifestPath | Out-Null }
    catch { $blocked = $true }
    if (-not $blocked) { throw "FAILED: Preflight allowed $Label" }
    Write-Host "PASS: rejected $Label"
}

try {
    foreach ($relative in @('BombSquad.Desktop.exe', 'Assets/AppIcon.ico', 'a.txt')) {
        $path = Join-Path $source ($relative.Replace('/', '\'))
        New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
        [System.IO.File]::WriteAllText(
            $path, "synthetic: $relative", [System.Text.UTF8Encoding]::new($false)
        )
    }
    $good = Join-Path $root 'good.zip'
        $archive = [System.IO.Compression.ZipFile]::Open(
        $good,
        [System.IO.Compression.ZipArchiveMode]::Create
    )
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath $source -Recurse -File)) {
            $entryName = $file.FullName.Substring(
                $source.Length + 1
            ).Replace('\', '/')

            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $archive,
                $file.FullName,
                $entryName
            ) | Out-Null
        }
    }
    finally {
        $archive.Dispose()
    }
    $entries = @()
    [long]$bytes = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $source -Recurse -File | Sort-Object FullName)) {
        $name = $file.FullName.Substring($source.Length + 1).Replace('\', '/')
        $entries += [ordered]@{
            path = $name
            sizeBytes = [long]$file.Length
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        $bytes += [long]$file.Length
    }
    $manifest = [ordered]@{
        publishFileCount = $entries.Count
        publishTotalBytes = $bytes
        files = $entries
    }
    $json = Join-Path $root 'good.json'
    [System.IO.File]::WriteAllText(
        $json, (ConvertTo-Json -InputObject $manifest -Depth 8),
        [System.Text.UTF8Encoding]::new($false)
    )

    & $validator -ZipPath $good -ManifestPath $json

    $extra = Join-Path $root 'extra.zip'
    Copy-Item -LiteralPath $good -Destination $extra
    Add-ZipEntry -ArchivePath $extra -EntryName 'unlisted.txt'
    Assert-Blocked -Label 'undeclared ZIP file' -ArchivePath $extra -ManifestPath $json

    $traversal = Join-Path $root 'traversal.zip'
    Copy-Item -LiteralPath $good -Destination $traversal
    Add-ZipEntry -ArchivePath $traversal -EntryName '../outside.txt'
    Assert-Blocked -Label 'path traversal ZIP entry' -ArchivePath $traversal -ManifestPath $json

    $collision = Join-Path $root 'collision.zip'
    Copy-Item -LiteralPath $good -Destination $collision
    Add-ZipEntry -ArchivePath $collision -EntryName 'A.TXT'
    Assert-Blocked -Label 'case-colliding ZIP entries' -ArchivePath $collision -ManifestPath $json

    $badSize = Join-Path $root 'size.json'
    $manifest.files[0].sizeBytes = [long]$manifest.files[0].sizeBytes + 1
    $manifest.publishTotalBytes = [long]$manifest.publishTotalBytes + 1
    [System.IO.File]::WriteAllText(
        $badSize, (ConvertTo-Json -InputObject $manifest -Depth 8),
        [System.Text.UTF8Encoding]::new($false)
    )
    Assert-Blocked -Label 'manifest length mismatch' -ArchivePath $good -ManifestPath $badSize

    Write-Host 'PASS: All five synthetic ZIP entry preflight scenarios.' -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}

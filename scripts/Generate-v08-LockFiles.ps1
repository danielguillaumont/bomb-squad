#requires -Version 5.1
<#
BOMB SQUAD v0.8 / Slice 2: Generate and verify NuGet lock files on Windows.
Run from repository root after the guarded installer succeeds.
Does not execute untrusted PowerShell source or modify application logic.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
if ([System.IO.Path]::GetFullPath((Get-Location).Path) -ne
    [System.IO.Path]::GetFullPath($repo)) {
    throw 'Run from the BOMB SQUAD repository root. Stop.'
}
if ((& git branch --show-current).Trim() -ne 'feat/v08-windows-distribution') {
    throw 'Wrong Git branch. Stop.'
}

$solution = Join-Path $repo 'BombSquad.slnx'
$desktop = Join-Path $repo 'src\BombSquad.Desktop\BombSquad.Desktop.csproj'
$expected = @(
    'src\BombSquad.Core\packages.lock.json',
    'src\BombSquad.Rules\packages.lock.json',
    'src\BombSquad.Analysis\packages.lock.json',
    'src\BombSquad.Cli\packages.lock.json',
    'src\BombSquad.Desktop\packages.lock.json',
    'tests\BombSquad.Tests\packages.lock.json'
)

Write-Host "`n=== GENERATE SOLUTION LOCK FILES ===" -ForegroundColor Cyan
& dotnet restore $solution
if ($LASTEXITCODE -ne 0) { throw 'Solution restore failed. Stop.' }

Write-Host "`n=== GENERATE WINUI DESKTOP LOCK FILE ===" -ForegroundColor Cyan
& dotnet restore $desktop
if ($LASTEXITCODE -ne 0) { throw 'Desktop restore failed. Stop.' }

foreach ($relative in $expected) {
    $file = Join-Path $repo $relative
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Missing NuGet lock file: $relative. Stop."
    }
    try { $json = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json }
    catch { throw "Invalid lock JSON at ${relative}: $($_.Exception.Message)" }
    if ($null -eq $json.dependencies) {
        throw "Lock file has no dependency map: $relative"
    }
    Write-Host "PASS: $relative" -ForegroundColor Green
}

$desktopLock = Get-Content -LiteralPath (Join-Path $repo 'src\BombSquad.Desktop\packages.lock.json') -Raw | ConvertFrom-Json
$topPackages = @{
    'Microsoft.Windows.SDK.BuildTools' = '10.0.28000.2957'
    'Microsoft.Windows.SDK.BuildTools.WinApp' = '0.7.1'
    'Microsoft.WindowsAppSDK' = '2.6.5'
}
foreach ($package in $topPackages.Keys) {
    $seen = $false
    foreach ($framework in $desktopLock.dependencies.PSObject.Properties) {
        $entry = $framework.Value.PSObject.Properties[$package]
        if ($null -ne $entry) {
            $seen = $true
            $actual = [string]$entry.Value.resolved
            if ($actual -ne $topPackages[$package]) {
                throw "Unexpected resolved version of ${package}: $actual"
            }
        }
    }
    if (-not $seen) { throw "Missing direct package in desktop lock file: $package" }
    Write-Host "PASS: $package = $($topPackages[$package])" -ForegroundColor Green
}

Write-Host "`n=== VERIFY SOLUTION LOCKED RESTORE ===" -ForegroundColor Cyan
& dotnet restore $solution --locked-mode
if ($LASTEXITCODE -ne 0) { throw 'Solution locked restore failed. Stop.' }

Write-Host "`n=== VERIFY DESKTOP LOCKED RESTORE ===" -ForegroundColor Cyan
& dotnet restore $desktop --locked-mode
if ($LASTEXITCODE -ne 0) { throw 'Desktop locked restore failed. Stop.' }

Write-Host "`nPASS: SIX LOCK FILES CREATED AND BOTH GRAPHS VERIFIED." -ForegroundColor Green
Write-Host 'NEXT: Run Release tests, Desktop Debug build and publish probe.'
& git status --short

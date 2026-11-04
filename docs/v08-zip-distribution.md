# BOMB SQUAD v0.8 - Preview ZIP distribution (Slice 3)

Status: local proof only; not a GitHub Release and not an approved installer.

## Goal

Turn a successful **unpackaged**, **win-x64**, self-contained Release publish
into a downloadable archive without altering the application or its dependencies.
Retain all files from the publish folder; the EXE is not a standalone binary.

## Requirements

- Work on `feat/v08-windows-distribution` containing Slice 2 commit `6d01422`.
- Use Windows PowerShell 5.1 or later on Windows.
- Generate a successful publish with `scripts/Publish-v08-UnpackagedProbe.ps1`.
- Use the `publish` folder from that successful probe; no other folder is accepted.
- Ensure adequate free disk space for the compressed archive and extracted copy.

## Build the local preview ZIP

From the repository root, after a successful publish:

```powershell
$latest = Get-ChildItem $env:TEMP -Directory -Filter 'BombSquad-v08-PublishProbe-*' |
    Where-Object { Test-Path (Join-Path $_.FullName 'publish-probe-summary.txt') } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if ($null -eq $latest) { throw 'No successful publish probe was found.' }
$publish = Join-Path $latest.FullName 'publish'
& .\scripts\Build-v08-DistributionZip.ps1 -PublishDirectory $publish
```

The tool prints a new `BombSquad-v08-ZipProbe-<GUID>` temp directory with:

- `BOMB-SQUAD-v0.8-preview-win-x64.zip` - complete publish folder contents
- `BOMB-SQUAD-v0.8-preview-win-x64.manifest.json` - SHA-256 and size of each file, the ZIP hash, source commit, and release caveats
- `SHA256SUMS.txt` - conventional SHA-256 checksums for the ZIP and manifest

The ZIP is generated outside Git. No files in `src`, `scripts`, or `docs` are
modified by the build operation. The generated output must not be committed.

## Verify contents and integrity

```powershell
$bundle = Get-ChildItem $env:TEMP -Directory -Filter 'BombSquad-v08-ZipProbe-*' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($null -eq $bundle) { throw 'No local ZIP bundle was found.' }
& .\scripts\Verify-v08-DistributionZip.ps1 -BundleDirectory $bundle.FullName
```

The verifier checks `SHA256SUMS.txt`, reads the external manifest, checks ZIP
entry path safety, extracts into a fresh temp folder, and verifies **every**
extracted file's SHA-256 and byte count, including icons and the EXE.

Then launch the **extracted** `BombSquad.Desktop.exe` using `Start-Process` with
its extraction directory as the working directory, and test:

- Window icon and header shield are visible.
- Built-in sample shows 6 commands, 6 findings, 0 parser errors.
- Paste inspection and report comparison still work.

## Security and distribution boundaries

- This local ZIP is **unsigned** and unverified on a clean Windows machine.
- SHA-256 checks that files match a manifest; it does **not** authenticate
  a publisher or guarantee source integrity. Signing is evaluated later.
- Users must extract the **entire** ZIP, not run the EXE from inside the archive.
- Do not run any inspected PowerShell source; the product examines text only.
- This preview is not installed, registered, auto-updated, or publicly released.
- A second ZIP built at a different time may not have the exact same bytes due
  to ZIP metadata or build timestamps. Dependency lock files do not guarantee
  bit-for-bit binary reproducibility.
- The clean-machine and CI distribution gates remain for v0.8 Slice 4.

## Next

Commit the two `scripts` files and this doc after local verification.
The generated ZIP/manifest/checksums stay outside Git and should not be
uploaded as an official GitHub Release yet.

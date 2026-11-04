# v0.8 / Slice 4 - Windows distribution CI and clean-machine QA

## Goal

Add a Windows GitHub Actions job that **builds a new self-contained publish**, creates the
preview ZIP and manifest from that exact publish, verifies the archive and every extracted
file hash, and uploads the three output files as a **temporary workflow artifact**.
This is a CI demonstration, **not** a GitHub Release, installer, signature, or security
certification.

## Changes

- `.github/workflows/windows-distribution.yml` - standalone distribution pipeline;
  does not replace the existing Windows CI jobs.
- `scripts/Run-v08-DistributionCI.ps1` - coordinates the existing Slice 1/3 scripts.
- `scripts/Build-v08-DistributionZip.ps1` - permits GitHub Actions detached HEAD
  checkouts while keeping the local feature-branch and ancestral commit guards.
- `docs/v08-ci-and-clean-machine-test.md` - this handoff document.

The pipeline uses read-only repository permissions, exact NuGet lock-file restores,
Release tests, an unpackaged self-contained win-x64 publish, ZIP integrity verification,
then a 14-day preview artifact upload. CI runs on feature-branch pushes, main pushes,
and PRs targeting main. The build is **not signed**.

## How to verify

1. On Windows, from `feat/v08-windows-distribution`, run
   `& .\scripts\Run-v08-DistributionCI.ps1` (may consume >300 MiB of temporary space).
2. Review the `PASS: v0.8 DISTRIBUTION CI PIPELINE VERIFIED.` message.
3. Run `git diff --check` and inspect that only the three new files plus the one
   scoped ZIP-builder modification are present.
4. Commit and push to the feature branch only after the local smoke pass.
5. On GitHub, open **Actions > Windows Distribution Preview**. Verify the
   `Publish, ZIP, Verify (win-x64)` job succeeds and that the artifact appears.
6. Download the artifact from the workflow run; it contains the **preview ZIP,
   manifest JSON, and SHA256SUMS.txt**. Do not treat it as a public release.

## Required independent Windows test (after CI)

Do this on a **fresh Windows 11 x64 VM or a second Windows PC** without Visual Studio,
Windows App SDK development packages, or the .NET SDK installed. A Windows 11 VM
on the same developer PC is still a useful isolation test if no second PC is available.

- Record Windows edition/build, CPU architecture, and whether relevant runtimes
  were already installed; avoid assuming a development PC proves portability.
- Transfer the exact workflow ZIP and checksums and verify the downloaded ZIP
  against the published SHA256SUMS.txt value.
- Extract **all** ZIP contents to a new user-writable directory.
- Launch `BombSquad.Desktop.exe` from that extracted folder. Check shield/icon
  display, startup, sample 6 commands / 6 findings / 0 parse diagnostics, paste
  inspection, safe JSON export, and report comparison with sample snapshots.
- Relaunch after closing. Check for missing runtime prompts, crashes, icon
  failures, file-picker issues, Windows warnings, and application logs.
- Record observed failures and screenshots; do **not** hide platform protections,
  disable SmartScreen or antivirus, or import untrusted signing certificates.
- The build is unsigned. Windows may show appropriate reputation warnings; any
  release plan must document this honestly. If Windows blocks launch, capture the
  exact warning rather than weakening security settings.
- Record explicit PASS/FAIL/NOT TESTED for each step and track any blockers.

No original PowerShell source may be executed for inspection; only the source
analysis application itself may be launched. Static matches are not safety verdicts.

## Known limits

- CI checks the *contents* and hashes of the ZIP, not a GUI launch on an isolated
  desktop. Successful GitHub CI does **not** prove the app works on a fresh Windows PC.
- SHA-256 gives integrity relative to the supplied manifest, not author authenticity.
- `v0.8-preview` is a test label and the desktop may still show `v0.7 development`
  until the v0.8 closeout.
- The exact .NET SDK used by `setup-dotnet@v5` is the latest available in the
  10.0.x channel. A future release-hardening pass should pin the SDK and/or
  record it in `global.json`, and consider immutable action commit hashes.
- A proper installer, signing, SBOM and public Release remain separate decisions.

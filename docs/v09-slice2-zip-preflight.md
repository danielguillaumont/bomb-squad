# BOMB SQUAD v0.9 / Slice 2 — Distribution ZIP preflight

**Status:** Development hardening, not a public release. **Base:** `5fe0a99` from `feat/v09-release-candidate`.

## What changes

- `scripts/Test-v09-ArchiveEntryPreflight.ps1` audits ZIP central-directory entries **without extracting**: rejects traversal, Windows-ambiguous paths, duplicate/case-colliding entries, symlinks, undeclared files and manifest length disagreements.
- `scripts/Test-v09-ArchiveEntryPreflight.Tests.ps1` builds tiny **synthetic** fixtures in a private temporary directory; tests one valid archive and four rejection cases. No PowerShell under inspection is executed.
- The existing v0.8 verifier calls the new preflight before extraction. Its existing SHA-256 verification of all extracted files remains mandatory.
- The ZIP builder accepts the v0.9 feature branch; the Windows distribution GitHub Actions workflow runs on v0.9 pushes and performs the regression check before publishing the preview ZIP.
- `docs/v09-release-candidate-gates.md` records the expanded Slice 2 scope.

## Acceptance on the Windows development machine

Run from `C:\Users\Daniel\Projects\bomb-squad` on `feat/v09-release-candidate`:

```powershell
& .\scripts\Test-v09-ArchiveEntryPreflight.Tests.ps1
if ($LASTEXITCODE -ne 0) { throw 'Archive test process failed.' }

dotnet test .\BombSquad.slnx -c Release
if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }

dotnet build .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug
if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed.' }

git status --short
git diff --check
```

PowerShell scripts throw on failure; do **not** treat an earlier `PASS` as proof if later output contains an exception. The full distribution CI job also performs locked restores, publishes a new win-x64 preview, creates a ZIP and checksum manifest, verifies every extracted hash, and uploads a temporary artifact. It is relatively CPU-, disk-, and time-intensive; prefer verifying that job on GitHub after pushing.

**Expected outcome:** regression fixtures pass; at least 317 xUnit tests pass, desktop builds; only the seven scoped files for this slice changed (two new scripts, four modified files, plus this document).

## Limits / further work

- Preflight sees ZIP names and uncompressed lengths. It is **not** an AV scan, code-signature check, publisher authentication or proof of application launch. The existing verifier still checks SHA-256 of every extracted file. The manifest and checksums travel with the artifact and do not establish author identity.
- The temporary GitHub Actions package is `v0.8-preview` by design: no code signing, installer, or public GitHub Release.
- **Fresh non-administrative Windows x64 machine without SDK:** not tested/deferred; required before a claim of portable v1.0 compatibility. Resource-constrained VirtualBox is not required to continue this development slice.
- Remaining Slice 2 work: CLI and WinUI error-handling smoke checks. Later v0.9 slices: independent machine verification (if available), release checklist, version policy, README and reviewed PR.

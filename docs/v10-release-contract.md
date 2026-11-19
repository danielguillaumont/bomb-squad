# BOMB SQUAD v1.0.0 — Release notes and scope

**Release:** v1.0.0, Windows x64, self-contained unpackaged ZIP (unsigned).

Bomb Squad is a local read-only PowerShell static inspector. It parses scripts without executing them and presents *potential* system changes for human review. It does not decide whether scripts are safe or malicious.

## Included in v1.0

- WinUI desktop, source-location evidence viewer, diagnostics, pasted snippets, explicit file batches and saved batch-report comparison.
- CLI inspection, JSON reports and optional CI exit-code gates.
- Six documented detection families: filesystem, security settings, registry, identity, tasks/services and dynamic execution.
- Automated regression tests and repeatable Windows x64 distribution generation, ZIP entry preflight, per-file SHA-256 verification and GitHub Actions validation.

## Version and compatibility

- **Product, ZIP and release tag:** `1.0.0` / `v1.0.0`.
- **Assembly/file version:** `1.0.0.0`.
- **Engine and rule-set identifiers:** remain `0.2.0-dev` for existing report comparison compatibility. These are not the product version.
- Historic `v08` scripts and prior development documents are retained as historical references.

## Packaging and release verification

From the repo root on Windows, close any running Bomb Squad window and run:

```powershell
dotnet test .\BombSquad.slnx -c Release
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Test-v09-ArchiveEntryPreflight.Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Run-v10-DistributionCI.ps1
```

The CI script publishes a multi-file, self-contained unpackaged `win-x64` app, builds `BOMB-SQUAD-v1.0.0-win-x64.zip`, produces a JSON integrity manifest plus `SHA256SUMS.txt`, and verifies the ZIP's files after safe extraction. The manifest records the exact source commit. **For the public release, build from the final `v1.0.0` tag (the same commit as `main` at tagging), and use the matching tag-run artifact.** Do not upload an artifact from an earlier PR merge or release branch to the public release.

## Boundaries

The ZIP is **unsigned**, and SHA-256 integrity verification is not publisher authentication. The app has been launched locally from an extracted archive; separate clean-machine testing was not performed, so broad fresh-machine compatibility is not claimed. A full extraction is required; this is not an installer.

There is no inspected-script execution, automatic remediation, malware certification, runtime control-flow proof, exhaustive alias/provider resolution, cloud upload or automatic update. **No findings does not mean safe.** Exported reports may include sensitive source excerpts or paths; review before sharing.

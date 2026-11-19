# v1.0 Release Contract (V10-B1)

**Status:** release candidate (`1.0.0-rc.1`), **not** a public or signed v1.0 release.

## Product scope

BOMB SQUAD is an offline-first, read-only PowerShell static inspector for Windows x64. It parses source without executing inspected PowerShell. Findings are conditional review leads, not malware verdicts, execution proof, or a declaration that unmatched scripts are safe.

Supported workflows at this checkpoint: selected `.ps1` inspection, bounded pasted snippets, explicit multi-file inspection, saved batch report comparison, CLI automation, and JSON export. Detection coverage is intentionally limited to six documented rule families.

## Version namespaces

- **Desktop/product prerelease:** `1.0.0-rc.1` (`v1.0.0 RC1` in the UI).
- **WinUI assembly/file version:** `1.0.0.0`; the product still has prerelease status, regardless of numeric Windows file metadata.
- **Engine/rule-set identifiers:** `0.2.0-dev` remain unchanged for report compatibility. They are not the desktop product version. Any future change requires explicit compatibility analysis and regression tests.
- **Current distribution workflow:** legacy **v0.8 preview** pipeline until V10-B2 migrates builder, verifier, CI, artifacts and documentation as one reviewed change. **Do not ship a v0.8 preview ZIP as v1.0.**

## Non-negotiable v1.0 gates

1. Release builds, automated tests, targeted CLI scenarios, and WinUI smoke tests pass on the tagged source.
2. Published Windows x64 bundle is self-contained; all packaged files, branding assets, manifest and SHA-256 values verify after fresh extraction.
3. An actual **non-administrative clean Windows x64 environment without developer tools** can extract and launch the published app and complete a sample inspection; record Windows version and prerequisites. If not done, disclose this explicitly and do not claim clean-machine compatibility.
4. Document Windows SmartScreen warnings / unsigned publisher identity accurately. SHA-256 is integrity evidence, **not** code signing or trusted publisher authentication.
5. UI labels, packaged binary version, ZIP filename, manifest, CI artifact and GitHub release/tag refer to the same release. The final `v1.0.0` tag is created **only after** replacing RC metadata and rerunning the gates.
6. README, release notes, screenshots and setup instructions reflect observed, validated behavior. Review JSON before sharing: reports may include sensitive paths or excerpts.

## Deliberately excluded

No automatic remediation, inspected-script execution, antivirus certification, full behavioral interpretation, broad directory traversal, cloud transmission, signed installer claims, or silent auto-update is implied by v1.0.

## Immediate follow-up

**V10-B2:** migrate the existing `v08` publish/ZIP/verification/CI scripts together, update naming and version checks coherently, preserve ZIP entry preflight and per-file SHA-256 verification, and exercise local and hosted end-to-end packaging. Keep generated binaries and archives outside the source repository.

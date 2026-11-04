# BOMB SQUAD v0.9 — release candidate gates

**Baseline:** v0.8 merged `main` at `f2cb3df` (PRs #9 and #10).
**Feature branch:** `feat/v09-release-candidate`.
**Scope of Slice 1:** Integration-test and document existing behavior; do not modify the parser, rule engine, CLI, WinUI, or distribution pipeline.

## Evidence carried forward from v0.8

- 303 automated tests passed on the user's Windows development machine before v0.9 branching.
- WinUI Desktop Debug build passed.
- A self-contained win-x64 preview ZIP was packaged and verified against a manifest (558 files).
- GitHub CI and GitHub Windows Distribution Preview workflows passed after PR checkout support was repaired.
- PR #9 merged Windows distribution; PR #10 merged README refresh and general pull-request CI support.
- Clean-machine compatibility, code signing and public installer/release remain **not verified**. A hash comparison against a bundled manifest is an integrity check, not publisher authentication.

## Slice 1 release gate map

| Gate | Automated test | Acceptance requirement |
| --- | --- | --- |
| No false safety verdict | RC01 | Zero findings must not be described as proof of safety; reports flag nonexecution |
| Never execute inspected PowerShell | RC02, RC04 | Inspected source is text only; marker payload never runs |
| Pasted input evidence stability | RC03 | Exact Unicode/CRLF source and evidence offsets remain intact |
| Partial batch failure visibility | RC05 | A parser failure and missing file must not hide other findings |
| Report data minimization | RC06 | Unmatched full script text is not embedded in batch JSON; matched evidence/paths can still appear |
| Source snapshot integrity | RC07 | Navigable source in memory is the text actually analyzed, even if the file changes |
| Real report delta classification | RC08–RC11 | New/removed findings are conditional; incomplete files are indeterminate; comparison reads only JSON |
| Report input validation | RC12–RC13 | An executed flag is rejected, and different engine versions make a comparison indeterminate |
| Safe report writes | RC14 | Single, batch and comparison export modes never overwrite existing JSON files silently |

These are regression gates and do not certify the application as safe, complete or production ready. Inspected PowerShell is never run by the test suite.

## Existing boundaries that remain in force

- Static AST analysis, not runtime evaluation or full PowerShell command resolution.
- Six implemented rule IDs; no findings does **not** establish that a script is safe.
- Parser diagnostics suppress risk rules for that affected input.
- Source-defined functions, qualified targets and command binding may be unresolved.
- File and pasted-input limits are 1 MiB; a batch accepts up to 50 explicitly supplied `.ps1` paths.
- Comparison uses report paths, rule IDs and exact evidence text; source-file moves, cosmetic evidence changes, or detector version changes can affect interpretation.
- JSON reports may expose local paths and matched source evidence; review before sharing.

## Remaining v0.9 work (do not mark done yet)

1. **Slice 1** — Run all v0.8 plus new release-gate tests on Windows, build Desktop, and review results. Commit only after success; confirm hosted CI.
2. **Slice 2** — Validate downloadable ZIP handling with pre-extraction archive safety checks and synthetic regression cases; follow with targeted CLI/WinUI smoke-test scenarios. Do not claim fresh-machine compatibility based on hosted CI.
3. **Slice 3** — Validate the actual downloadable preview on a fresh, non-administrative Windows x64 machine without the development SDK. If unavailable, mark the gate **BLOCKED/DEFERRED** rather than passing it. Verify launch, brand assets, sample, paste, file, batch, JSON export, comparison and relaunch.
4. **Slice 4** — Verify release documentation, version identifiers, warnings/limitations, distribution artifact and GitHub CI. Complete v0.9 checklist and merge a reviewed PR.

## Not yet cleared for a public v1.0 release

- Clean Windows x64 compatibility and non-administrator test are not verified.
- Executables are not code-signed and no installer has been validated.
- The toolchain is not fully immutable (e.g., .NET SDK 10.0.x floating feature channel and GitHub Actions major tags).
- Desktop product label and engine/rule-set versions have different purposes; consolidate user-facing version policy before calling a build v1.0.
- The rule set is partial and cannot make an execution-safety determination.

**Release rule:** v0.9 may be completed as a development release-candidate milestone with clearly documented blockers. No public release, signed-installer claim or clean-machine claim until those separate gates are actually verified.

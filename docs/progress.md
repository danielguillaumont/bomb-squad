# BOMB SQUAD - Development Progress

Last updated: 2026-10-28
Current milestone: v0.7 - Core completion and hardening (closeout candidate)
Development branch: feat/v07-v1-hardening
Base: v0.6 merged to `main` in PR #7 (`1093d95`)
Engine version: 0.2.0-dev
Rule set version: 0.2.0-dev

## Current Status

v0.6 was merged into `main` in PR #7. v0.7 development on `feat/v07-v1-hardening` adds safe paste inspection, an acceptance-gate audit, function-context and command-shadowing limitations, and explicit unresolved-target/incomplete-parsing notes.

Last verified checkpoint (2026-10-28, Slice 4):

- 297 automated tests passed, zero failures/skips.
- WinUI desktop built and launched locally.
- Manual tests covered paste inspection, defined functions, shadowed cmdlet names, unresolved `.exe`/module-qualified commands, and malformed PowerShell.
- GitHub Actions Windows CI #60 passed both test and WinUI build jobs for commit `1073a5f`.
- The feature branch was clean and synchronized with GitHub after Slice 4.

Slice 5 updates the v0.7 version display, accessibility metadata, release guidance, and adds six focused regression tests. **These changes must pass local Windows builds, manual keyboard/scaling checks, and hosted CI before v0.7 can be considered closed.** No signed installer or tested clean-machine distribution exists yet; that is planned for v0.8.

## Historical milestones

The sections below preserve earlier checkpoint notes for traceability. Older "pending" merge/checklist entries are historical, not the current v0.6 status.

## PREP - Completed

- Windows 11 and .NET 10 environment verified
- PowerShell AST parser feasibility demonstrated
- Valid and malformed PowerShell parsing tested
- Native WinUI 3 feasibility prototype launched
- Self-contained desktop publishing tested locally
- Initial architecture decisions documented

## v0.0 - Foundation Completed

- Five-project .NET solution established
- Core analysis contracts implemented
- Analysis, Rules, CLI, and Tests projects established
- Windows GitHub Actions workflow configured
- Pull request #1 merged into main

## v0.1 - Parsing Foundation Implemented

- System.Management.Automation 7.6.7 integrated
- System.Security.Cryptography.Pkcs 10.0.13 pinned
- Parser.ParseInput integrated without source execution
- AST command extraction implemented
- Source line, column, and offset tracking implemented
- Syntax diagnostics preserved
- Parsed and ParsedWithErrors statuses implemented
- Malformed scripts skip detection rules
- Nested commands and parser edge cases tested
- Static-only behavior covered by automated tests

## v0.2 - Detection Families Implemented

Six initial rule IDs:

- BS-FS-001: Selected filesystem deletion operations
- BS-SS-001: Selected Microsoft Defender preference changes
- BS-RG-001: Registry property changes with supported literal paths
- BS-ID-001: Selected local account and group changes
- BS-TS-001: Selected scheduled task and service changes
- BS-DE-001: Selected dynamic execution patterns

The rule engine produces findings with:
- Rule ID and detection family
- Source location and supporting evidence
- Review level and certainty
- Potential effect
- Explicit limitations
- Recommended review steps

All findings remain conditional. Detection does not prove
that a command would execute or produce a particular effect.

## v0.2 - CLI Features Implemented

- Built-in six-family demonstration
- Malformed PowerShell demonstration
- Real .ps1 file inspection
- File existence and extension validation
- 1 MiB file-size limit
- UTF-8 validation and recognized Unicode BOM support
- Structured JSON report export
- No-overwrite report behavior
- Optional --fail-on-findings flag
- Exit codes for findings, input errors, and parse errors
- Reusable samples/example.ps1 demonstration
- End-to-end CLI regression tests

Exit-code behavior with --fail-on-findings:

0 - Analysis completed without findings from supported rules
1 - One or more findings need review
2 - Invalid arguments, input, or report error
3 - Parser errors prevented rule evaluation

Without the flag, completed analysis may exit 0 even when
findings or parser errors are present.

## v0.3 - Desktop Preview Implemented

- Created and built `BombSquad.Desktop` as a WinUI 3 / Windows App SDK project
- Refined the native application into the distinct Precision Desk visual identity
- Integrated a native `.ps1` file picker with shared safe-reading restrictions
- Reused the six detection families and conditional findings from the analysis engine
- Added selectable findings, evidence, potential effects, limitations, and recommended review steps
- Built a read-only Source Explorer with original line numbers and source locations
- Moved the source reader into a dedicated Source Focus workspace, with Back to findings navigation
- Preserved valid-no-match and malformed-input messaging without claiming a safety verdict
- Added a native JSON Save dialog using a shared serializer with the CLI
- Added tests for file reading, source line mapping, and JSON serialization
- Added a separate hosted Windows CI job that compiles the WinUI desktop project

Local manual verification covered `samples/example.ps1`, a clean one-command test, a malformed string-literal test, finding-to-source navigation on lines 10 and 11, and valid/malformed JSON export. GUI launch and interaction were validated locally, not in headless CI.

## Verified Test Checkpoint

The historical v0.2 baseline was 148 passing tests before the desktop additions. The current v0.3 baseline is 176.

Date: 2026-10-17
Configuration: Release
Framework: .NET 10
Result: 176 passed, 0 failed, 0 skipped

Coverage includes:
- Parser extraction and diagnostics
- Rule detection and false-positive cases
- Six-family integration
- Source offsets and evidence
- Missing, malformed, oversized, and invalid input
- CLI execution and file inspection
- JSON structure and report protection
- CI-compatible exit codes
- Non-execution checks using marker files
- Safe `.ps1` reader and Unicode/size validation
- Read-only source-document and line-number mapping
- Shared JSON serializer regressions for CLI and desktop

## Documentation and Automation

- Root README and design-system documentation updated for the implemented v0.3 desktop preview
- Architecture decision records and v0.2 milestones preserved
- Windows CI includes an existing .NET 10 build/test/CLI job plus a dedicated WinUI desktop compile job
- Hosted Windows CI run #29 passed both jobs on `feat/v03-desktop` (`d15ad95`)
- Desktop runtime interactions remain a local manual verification responsibility

## Known Limitations

- The rule set covers only selected PowerShell operations
- Runtime control flow is not evaluated
- Dynamic command targets are not fully resolved
- Aliases and command shadowing are not fully resolved
- PowerShell parameter binding is not fully evaluated
- System state and runtime effects are not inspected
- Parser errors cause all detection rules to be skipped
- No findings does not mean a script is safe
- Individual `.ps1` files are supported; batch scanning and folder analysis are not implemented
- No signed installer, verified clean-machine installation, or reproducible release package exists yet
- Headless CI compiles WinUI but does not exercise native dialogs and interactions
- JSON reports can contain source excerpts and sensitive local file paths

The inspected PowerShell source is never executed.

## v0.3 Pull Request and Merge Gate

- [x] v0.3 desktop compiles in local Debug configuration
- [x] Original five-project solution builds in Release
- [x] 176 automated tests pass
- [x] All six detection families remain static-only and conditional
- [x] File picker handles valid, clean, and malformed scripts
- [x] Source Focus navigates to the correct source line
- [x] JSON export and cancellation validated locally
- [x] Hosted Windows CI validates solution and WinUI build (#29)
- [x] Final docs reviewed and committed on `feat/v03-desktop`
- [x] PR opened against `main`, changes and checks reviewed
- [x] PR #4 merged into `main` and local `main` synchronized

## Deferred (post-v0.3)

- Parser-diagnostic navigation and further analysis hardening
- App icon and desktop presentation polish
- Keyboard accessibility and window-size / high-DPI test matrix
- Dependency license and advisory review for distributed builds
- Installer signing, clean-machine validation, and reproducible packaging
- Review production trimming and publishing warnings

## v0.4 - Parser Diagnostics and Desktop Polish

Implemented on `feat/v04-diagnostics`:

- Interactive parser diagnostic explorer with separate entries for multiple syntax errors.
- Source line and column navigation for parser diagnostics and inspection findings.
- Updated Windows application branding, including a unified BOMB SQUAD icon.
- Windows keyboard shortcuts for opening files, loading the sample, exporting reports, viewing source, and navigating back.
- Responsive desktop layouts for wide and narrow windows.
- Improved inspection metric layout and narrow-window footer readability.

Verification:

- 180 automated tests passed in Release configuration, with 0 failures and 0 skipped.
- WinUI desktop project built successfully.
- Manually inspected example, clean, malformed, and multiple-error PowerShell fixtures.
- Confirmed that parser errors prevent rule evaluation.
- Verified source navigation, report export, and responsive presentation.
- Hosted Windows CI passed for the preceding v0.4 feature changes; final pull-request checks remain to be verified.

Safety requirements remain unchanged:

- Supplied PowerShell source is never executed.
- Inspection is local, static, and read-only.
- Findings are conditional review leads, not proof of execution.
- No findings does not establish that a script is safe.

## v0.4 Pull Request and Merge Gate

- [x] Core and desktop functionality implemented
- [x] 180 automated tests pass
- [x] Local desktop build succeeds
- [x] Manual interface and navigation checks completed
- [x] Responsive-layout and branding changes committed
- [ ] Final documentation committed and pushed
- [ ] Pull request opened and Windows CI checks reviewed
- [ ] v0.4 merged into `main` and local repository synchronized

## Next Milestone

Complete the v0.4 documentation, verify the final Windows CI checks, merge the v0.4 pull request into `main`, and synchronize the local repository. Plan future enhancements on a new feature branch after the merge.

## v0.5 - Multi-file batch inspection

Implemented on `feat/v05-batch-inspection` and merged into `main` via PR #6 (`7e1d2e9`).

- Implemented shared batch analysis and JSON serialization.
- Added CLI multi-file inspection and export.
- Added desktop batch selection, file switching, and JSON export.
- Verified clean, matching, and malformed PowerShell inputs.
- Passed 210 automated tests and Windows desktop compilation.
- Passed Windows GitHub Actions on the feature branch.
- Verified exported batch reports indicate that source was not executed.

The rule set remains partial. Findings describe potential effects, not confirmed runtime behavior.

v0.5 closeout is complete. Signed installation and production distribution remain future work.
## v0.6 - Baseline Report Comparison

Implemented on `feat/v06-baseline-comparison`:

- Slice 1 (`8f450ba`): shared comparison engine, file-identity matching, finding multiset deltas, and indeterminate handling.
- Slice 2 (`6071c2d`): deterministic structured comparison JSON writer; `sourceExecuted: false`.
- Slice 3 (`0c78c99`): `--compare` CLI mode, optional `--json` and `--fail-on-new`, CI-friendly exit codes.
- Slice 4 (`c8a5b99`): WinUI baseline comparison workspace, per-file change register, evidence inspection, and native JSON export.

Verified on Slice 4: 246 Release tests; desktop Debug build; CLI smoke test; interactive desktop baseline/current selection, evidence and export; sample inspection unchanged; Windows CI run #53 passed both jobs.

Slice 5 closeout checklist:

- [ ] Four additional negative/edge-case report comparison tests pass in Release.
- [ ] Desktop Debug build succeeds with updated v0.6 development label.
- [ ] Desktop and CLI static-only comparison behaviors remain intact.
- [ ] Hosted Windows CI passes on the final closeout commit.
- [ ] PR against `main` opened, reviewed, merged, and local `main` synchronized.

Important limits: comparison uses matching report paths and exact evidence; it does not track renamed files or infer that disappeared patterns were remediated. Parser/input failures and incompatible engine/rule-set metadata are indeterminate. The original PowerShell source is never executed or reopened during comparison. GUI interactions are verified manually, not by headless CI.

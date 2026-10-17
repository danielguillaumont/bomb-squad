# BOMB SQUAD - Development Progress

Last updated: 2026-10-17
Current milestone: v0.3 - Desktop Foundation
Development branch: feat/v03-desktop
Engine version: 0.2.0-dev
Rule set version: 0.2.0-dev

## Current Status

v0.2 is merged into `main` (PR #3, merge commit `4a59f87`). The v0.3 desktop implementation is complete on `feat/v03-desktop`, pushed to GitHub, and undergoing final documentation and PR review. The WinUI frontend reuses the static-only .NET analysis engine; imported PowerShell source is never executed.

Latest verified checkpoint (2026-10-17):

- Release solution build and Debug desktop build passed locally
- **176 automated tests passed, 0 failed, 0 skipped**
- Real `.ps1` inspection, six detection families, and no-match/malformed states verified in the UI
- Dedicated Source Focus viewer navigates to the selected finding's original line
- Native JSON report export verified for valid and malformed samples; Save dialog cancellation is safe
- Desktop and CLI use the shared JSON serializer
- GitHub Actions Windows CI **run #29**, commit `d15ad95`: both build-and-test and WinUI desktop build jobs passed
- Working tree clean after CI commit `d15ad95`

The v0.3 feature branch is **not yet merged into `main`**. The installed/signed distribution, extensive keyboard/accessibility checks, and clean-machine installation remain future work.

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
- [ ] Final docs reviewed and committed on `feat/v03-desktop`
- [ ] PR opened against `main`, changes and checks reviewed
- [ ] PR merged and local `main` synchronized

## Deferred (post-v0.3)

- Parser-diagnostic navigation and further analysis hardening
- App icon and desktop presentation polish
- Keyboard accessibility and window-size / high-DPI test matrix
- Dependency license and advisory review for distributed builds
- Installer signing, clean-machine validation, and reproducible packaging
- Review production trimming and publishing warnings

## Next Milestone

Finish v0.3 documentation, verify hosted checks on the PR, merge into `main`, and confirm the repository is clean. Develop additional enhancements in a new post-merge feature branch rather than expanding the v0.3 scope.

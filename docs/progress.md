# BOMB SQUAD - Development Progress

Last updated: 2026-10-17
Current milestone: v0.2 - Detection and CLI Foundation
Development branch: feat/v02-rules
Engine version: 0.2.0-dev
Rule set version: 0.2.0-dev

## Current Status

The v0.2 detection and CLI features are implemented and verified
locally. The feature branch is pushed to GitHub.

Latest verified checkpoint:
- Release build successful
- 148 automated tests passed
- 0 failed, 0 skipped
- All six detection families integrated
- Real .ps1 file inspection working
- JSON reporting working
- Optional CI/CD exit codes working

The v0.2 branch has not yet been verified as merged into main.
GitHub Actions results still require explicit verification.

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

## Verified Test Checkpoint

Date: 2026-10-17
Configuration: Release
Framework: .NET 10
Result: 148 passed, 0 failed, 0 skipped

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

## Documentation and Automation

- Root README updated for the v0.2 development implementation
- Architecture decision records preserved
- Windows GitHub Actions workflow already exists
- CI workflow enhancement in progress
- Remote CI execution and final status not yet verified

## Known Limitations

- The rule set covers only selected PowerShell operations
- Runtime control flow is not evaluated
- Dynamic command targets are not fully resolved
- Aliases and command shadowing are not fully resolved
- PowerShell parameter binding is not fully evaluated
- System state and runtime effects are not inspected
- Parser errors cause all detection rules to be skipped
- No findings does not mean a script is safe
- Only individual .ps1 files are supported by the CLI
- The native Windows desktop application is not integrated

The inspected PowerShell source is never executed.

## Outstanding Release Concerns

- Verify GitHub Actions on the feature branch
- Review pull request and merge strategy
- Perform additional security and parser hardening
- Review dependency licenses and advisories
- Validate clean-machine installation and distribution
- Review previous desktop publishing trim warnings
- Validate production WinUI 3 dependency support
- Prepare reproducible release artifacts

## Next Milestone

Finish v0.2 documentation and CI verification.

Afterward:
1. Review remaining parser and rule coverage gaps
2. Strengthen security and release validation
3. Prepare the next product milestone and desktop UI work

## v0.2 Completion Gate

- All projects build in Release
- Automated tests pass
- All six families are integrated
- Real file inspection remains static-only
- JSON and CLI exit-code behavior is verified
- Windows GitHub Actions passes
- Documentation reflects actual implementation
- No universal safety verdict is implied
- Feature branch is reviewed and merged appropriately

# BOMB SQUAD

**Know what a script could change before I run it.**

BOMB SQUAD is an offline-first, read-only PowerShell Change & Risk Inspector built with C# and .NET 10.

I built it around a simple problem: PowerShell scripts can modify files, security settings, registry values, accounts, and system services. Before running an unfamiliar script, I want to understand the changes it might attempt.

BOMB SQUAD statically analyzes PowerShell source code, identifies supported potentially consequential operations, and explains the findings with source locations, evidence, uncertainty, and recommended review steps.

**The inspected PowerShell script is never executed.**

## What works today

The current v0.7 development implementation includes:

- PowerShell parsing using the PowerShell Abstract Syntax Tree (AST).
- Six rule families for selected potentially consequential operations.
- Analysis of real `.ps1` files without executing them.
- Source line, column, and character-offset tracking.
- Parser diagnostics and explicit handling of malformed scripts.
- Evidence-backed findings with uncertainty and limitations.
- Structured JSON report export for individual scripts and multi-file batches.
- Optional CI/CD exit codes for automated review gates.
- Automated tests covering detection, integration, CLI behavior, desktop support code, and non-execution.
- A native Windows desktop application built with WinUI 3 and Windows App SDK.
- A file picker, findings review, source-line navigation, and a dedicated read-only source workspace.
- A native JSON Save dialog using the same report serializer as the CLI.
- Windows GitHub Actions jobs for CLI/tests and desktop compilation.
- Two-snapshot baseline comparison for previously exported batch JSON reports in CLI and WinUI.
- Comparison JSON export with newly, still, and no-longer-detected findings and incomplete-coverage status.

The CLI and desktop application share the same static analysis and report-comparison engines. The desktop is a **v0.7 development preview**, not a signed or packaged release. The last verified v0.7 baseline included **297 passing automated tests** and successful Windows CI (#60, commit `1073a5f`). The final v0.7 closeout tests, accessibility checks, and milestone merge remain pending until verified.

## What's new in v0.7

v0.7 focuses on the original v1 inspection journey and honest uncertainty reporting, not additional detection families.

- **Paste PowerShell snippet** accepts UTF-8 text up to 1 MiB for read-only AST inspection without writing a `.ps1` file.
- Function-body findings explain that defining a function does not invoke it. Built-in-specific matches are conservatively withheld when source-defined function names collide; lexical scope and runtime binding are **not** resolved.
- Incomplete PowerShell source produces parser diagnostics and skips all detection rules rather than implying clearance.
- Recognizable external and module/path-qualified command names produce unresolved-target review notes; this is not runtime command discovery.
- Added acceptance-gate and regression tests in `docs/v07-acceptance-audit.md`, plus a v0.7 manual closeout checklist.

The analyzer never executes the supplied source. Zero findings does not establish safety. The app remains a development preview; clean-machine distribution is planned for v0.8.

## What's new in v0.4

The v0.4 development work improves the Windows desktop inspection experience:

- Interactive parser diagnostics with multiple syntax errors listed separately.
- Source navigation to the relevant line and column for findings and parser diagnostics.
- Unified BOMB SQUAD branding across the desktop application and Windows icons.
- Keyboard shortcuts for common inspection and navigation actions.
- Responsive layouts for wide and narrow application windows.
- Improved footer readability and reporting feedback.

The desktop remains a development preview, not a signed or packaged release. All PowerShell inspection remains static and read-only. Supplied scripts are never executed.

## What's new in v0.5

v0.5 introduces multi-file PowerShell inspection while preserving the existing offline-first, read-only static analysis model.

- Batch inspection of multiple explicitly selected `.ps1` files.
- Independent parsing, findings, and diagnostics for each file.
- Batch-level statistics for files, commands, findings, and errors.
- Continued processing of other files when one contains syntax errors.
- Multi-file CLI inspection and combined JSON report export.
- Desktop batch file selection and switching between individual results.
- Batch JSON export containing results for every selected file.
- Expanded automated regression coverage.

Batch inspection reads only explicitly selected files. It does not recursively scan folders or execute submitted PowerShell.

The desktop remains a development preview, not a signed or packaged application.

## What's new in v0.6

v0.6 adds **baseline comparison** of two previously exported v0.5-compatible batch JSON reports. The comparison feature never opens, parses, or executes the `.ps1` paths described by those reports.

- New `--compare <baseline.json> <current.json>` CLI mode, with optional `--json <new-report.json>` export.
- Optional `--fail-on-new` CI gate: `0` when the comparison is complete and no new findings are detected, `1` for one or more new matches, `2` for invalid inputs/export errors, and `3` for incomplete comparison coverage. Without the flag, a completed comparison may exit `0` despite new findings or incomplete coverage.
- Desktop **Compare inspection reports** workspace for selecting two batch JSON snapshots, viewing per-file status and exact finding evidence, and exporting a comparison report.
- Finding changes are classified as **newly detected**, **still detected**, or **no longer detected**. Occurrences are matched by rule ID and *exact source evidence*; moving unchanged evidence to another line does not count as new.
- Parser failures, input failures, and engine/rule-set mismatches yield **indeterminate**, rather than falsely reporting resolved findings. Files appearing in only one snapshot are explicitly unmatched.

**Interpretation matters:** these are static pattern matches, not runtime facts. A no-longer-detected pattern is **not** proof that code or a system is safe. Exact-evidence edits may look like both new and removed matches. Full report paths are used as file identities, so renamed/moved scripts are not tracked. Reports can contain sensitive paths and source excerpts.

### Compare two saved batch reports from the CLI

First save a baseline batch report, then save a current report after the source changes. Use unique output filenames: the CLI deliberately does not overwrite existing report files.

```powershell
$cli = ".\src\BombSquad.Cli\BombSquad.Cli.csproj"
$script = ".\samples\example.ps1"

# Capture the baseline at its original point in time.
dotnet run --project $cli -c Release -- --batch $script --json ".\baseline.json"

# Re-inspect the same script *after* making your own source changes.
dotnet run --project $cli -c Release -- --batch $script --json ".\current.json"

# Compare saved reports without reopening either .ps1 source.
dotnet run --project $cli -c Release -- --compare ".\baseline.json" ".\current.json" --json ".\comparison.json" --fail-on-new
```

These commands are a workflow illustration: do not run the two batch captures back-to-back unchanged if you intend to demonstrate new findings. `--fail-on-new` returning `1` or `3` is an intentional CI signal; inspect the comparison before drawing conclusions. Original PowerShell content is never executed.

### Compare saved reports in the desktop app

Click **Compare inspection reports**, choose the baseline (older) and current (newer) batch JSON snapshots, and inspect the summary, per-file coverage, changed findings, and exact evidence. **Export comparison** uses the native Windows Save dialog. **Back to inspection** returns to the normal source examination workspace. The comparison operates on the saved JSON only.

## Quick start

Requirements:

- .NET 10 SDK
- Windows with the Windows App SDK development/build prerequisites for the desktop application (Windows 11 is the verified development environment).

Clone the repository and build the solution:

```powershell
git clone https://github.com/danielguillaumont/bomb-squad.git
cd bomb-squad

dotnet build .\BombSquad.slnx -c Release
```

Run the built-in demonstration:

```powershell
dotnet run --project .\src\BombSquad.Cli\BombSquad.Cli.csproj -c Release
```

Inspect the included PowerShell sample:

```powershell
dotnet run --project .\src\BombSquad.Cli\BombSquad.Cli.csproj -c Release -- --file ".\samples\example.ps1"
```

The sample demonstrates all six implemented detection families. Its example commands are inside a non-executing conditional block.

To inspect your own script, replace the sample path with a `.ps1` file path.

## Windows desktop preview (v0.6)

The native WinUI 3 desktop application is built separately from `BombSquad.slnx`. On Windows, build and launch it with:

```powershell
dotnet build .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug
dotnet run --project .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug
```

Use **Open .ps1 file** to choose a local PowerShell script for read-only AST inspection. **Try sample** loads the included six-family demonstration. The review workspace displays findings, supporting evidence, potential effects, limitations, and source locations. **Inspect source** opens a dedicated, line-numbered source viewer focused on the selected finding; **Back to findings** returns to the review workspace.

Use **Export report** to save the current analysis as JSON through the native Windows Save dialog. The desktop uses the shared JSON schema; Windows asks for confirmation before an existing file is replaced. Cancelling an Open or Save dialog leaves the current analysis intact.

Valid scripts with zero supported matches explicitly say **no matching findings**, not *safe*. For malformed scripts, the interface shows parser diagnostics and identifies that the detection rules were skipped. The inspected `.ps1` source is **never executed**.

At this stage the repository does not provide a signed installer or a verified clean-machine distribution package. Desktop compilation is checked in Windows CI; GUI interactions were verified locally.

### Multi-file desktop inspection

Use **Open batch of .ps1 files** to select multiple local PowerShell scripts.

The **Batch inspection** panel displays overall results. Use **File to examine** to switch between individual scripts, findings, parser diagnostics, and source evidence.

Use **Export batch JSON** to save one report containing all selected files.

Scripts containing syntax errors are identified separately. Detection rules are skipped for those scripts, while other valid files can still be inspected. Submitted PowerShell is never executed.

## Detection coverage

BOMB SQUAD currently implements six rule IDs:

| Rule | Family | Example |
|---|---|---|
| BS-FS-001 | Filesystem | `Remove-Item` |
| BS-SS-001 | Security Settings | `Set-MpPreference` |
| BS-RG-001 | Registry | `Set-ItemProperty` targeting a literal registry path |
| BS-ID-001 | Local Identity | `Add-LocalGroupMember` |
| BS-TS-001 | Tasks and Services | `Register-ScheduledTask`, `New-Service`, `Set-Service` |
| BS-DE-001 | Dynamic Execution | `Invoke-Expression`, `iex`, expression-based invocation |

These are selected patterns, not complete coverage of PowerShell behavior.

Findings describe **potential operations**, not confirmed actions. Command aliases, shadowing, dynamic values, target providers, parameter binding, and runtime control flow are not fully resolved.

A finding may appear inside an inactive conditional or function because the current engine does not evaluate whether that code will execute.

## JSON reports

Export a structured analysis report:

```powershell
$report = Join-Path $env:TEMP (
    "bomb-squad-" +
    [guid]::NewGuid().ToString("N") +
    ".json"
)

dotnet run --project .\src\BombSquad.Cli\BombSquad.Cli.csproj -c Release -- --file ".\samples\example.ps1" --json $report
```

Reports include:

- Source file and analysis versions
- Parse status and diagnostic information
- Rule IDs, finding families, and review levels
- Exact source locations and supporting evidence
- Potential effects and suggested review steps
- Unresolved constructs and analysis limitations
- An explicit statement that the source was not executed

The CLI refuses to overwrite existing report files. In the desktop app, the native Save dialog requests confirmation before replacing an existing file.

Reports may contain excerpts and absolute paths from the inspected script. Treat them as potentially sensitive and share them deliberately.

## CI/CD integration

Use `--fail-on-findings` to make BOMB SQUAD return a nonzero exit code when an implemented rule reports a finding.

```powershell
dotnet run --project .\src\BombSquad.Cli\BombSquad.Cli.csproj -c Release -- --file ".\samples\example.ps1" --fail-on-findings
```

JSON export can be combined with the same flag.

| Exit code | Meaning |
|---|---|
| 0 | Analysis completed without findings from implemented rules |
| 1 | One or more findings require review |
| 2 | Invalid input, arguments, or report error |
| 3 | Parser errors prevented rule evaluation |

These codes apply when `--fail-on-findings` is enabled. Without the flag, completed analysis can return 0 even when findings or parser diagnostics exist.

Exit code 0 does not certify that a script is safe.

## Architecture

Parsing, detection, and reporting are shared between both frontends. Neither frontend executes imported PowerShell source.

```text
PowerShell source (.ps1 or built-in sample)
                  |
                  v
        BombSquad.Analysis
          PowerShell AST
          + diagnostics
                  |
                  v
          BombSquad.Rules
                  |
                  v
       Evidence-backed findings
              /       \
             v         v
     BombSquad.Cli   BombSquad.Desktop (WinUI 3)
       CLI output    Findings + Source Focus
       exit codes    Native Open/Save dialogs
             \         /
              v       v
     Shared JSON report serializer
```

### Projects

| Project | Responsibility |
|---|---|
| BombSquad.Core | Shared models, findings, source spans, and contracts |
| BombSquad.Analysis | AST parser, analysis orchestration, safe source loading, line mapping, and shared JSON serialization |
| BombSquad.Rules | Six supported detection rule families and rule evaluation |
| BombSquad.Cli | Console inspection, exit codes, and CLI JSON export |
| BombSquad.Desktop | Native WinUI 3 interface, file selection, Source Focus, and Save dialog |
| BombSquad.Tests | Unit, integration, static-only safety, file handling, CLI, and report regression tests |

`BombSquad.slnx` contains the original five non-desktop projects; the WinUI desktop project is built separately and has its own GitHub Actions job.

## Testing

Build and run the complete automated test suite:

```powershell
dotnet build .\BombSquad.slnx -c Release
dotnet test .\BombSquad.slnx -c Release --no-build
```

The **246 automated tests verified in Slice 4**, plus four new Slice 5 regression tests pending verification, cover positive detections, nonmatching commands, parser errors, file decoding and limits, source line mapping, report generation, CLI input validation, and checks that inspected PowerShell source does not execute.

Build the desktop separately with the Debug command in the Windows desktop section. `.github/workflows/windows-ci.yml` has separate jobs for the CLI/test solution and WinUI desktop compilation. Windows CI also passed on the v0.6 feature branch at Slice 4 (run #53), including the .NET 10 build/test and WinUI desktop compilation jobs. These checks do not verify interactive GUI functionality.

## Safety and limitations

BOMB SQUAD is a static inspector, not a PowerShell execution environment.

Core design principles:

1. Parse source text; never execute imported scripts.
2. Explain potential behavior without claiming runtime certainty.
3. Preserve evidence, source locations, and known limitations.
4. Keep the analysis engine separate from the user interface.
5. Keep analysis local without requiring accounts or AI APIs.

The current version has a partial rule set. It does not resolve every dynamic command, evaluate runtime conditions, or prove what a script will do on a particular system.

**No findings does not mean a script is safe.**

BOMB SQUAD is not an antivirus engine, malware sandbox, universal safety checker, or replacement for professional code review.

## Roadmap

- [x] v0.1 - PowerShell AST parsing foundation
- [x] v0.2 - Six detection families, real file inspection, JSON reporting, and CI-friendly exit codes (merged to `main`)
- [x] v0.3 implementation - Native WinUI 3 preview, Precision Desk, Source Focus, file picker, and JSON export
- [x] v0.3 verification - 176 local tests and both hosted Windows CI jobs passed
- [x] v0.3 closeout - Final documentation and PR #4 merged into `main` at `65b6673`
- [x] v0.4 development - Interactive parser diagnostics, source navigation, Windows branding, keyboard shortcuts, and responsive desktop layout
- [x] v0.4 local verification - 180 automated tests passing; desktop scenarios manually tested
- [x] v0.4 merge - PR #5 merged into main
- [x] v0.5 implementation - Batch analysis, multi-file CLI, desktop file switching, and batch JSON export
- [x] v0.5 verification - 210 tests passing, Windows CI green, and desktop batch scenarios tested
- [x] v0.5 merge - PR #6 merged into `main` (`7e1d2e9`)
- [x] v0.6 implementation - Batch JSON baseline comparison in shared engine, CLI, and WinUI desktop
- [x] v0.6 Slice 4 verification - 246 tests passing, hosted Windows CI #53 green, and desktop comparison/export tested
- [ ] v0.6 closeout - Final regression checks, documentation, and pull request into `main`
- [ ] Future - Accessibility audit, additional detection hardening, and expanded testing
- [ ] Future - Signed installer, clean-machine testing, and release distribution

See [development progress](docs/progress.md) and the architecture decision records in [docs/adr](docs/adr).

## Technology

C# | .NET 10 | PowerShell AST | WinUI 3 | Windows App SDK | xUnit | Git | GitHub Actions

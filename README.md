# BOMB SQUAD

**Know what a script could change before I run it.**

BOMB SQUAD is an offline-first, read-only PowerShell Change & Risk Inspector built with C# and .NET 10.

I built it around a simple problem: PowerShell scripts can modify files, security settings, registry values, accounts, and system services. Before running an unfamiliar script, I want to understand the changes it might attempt.

BOMB SQUAD statically analyzes PowerShell source code, identifies supported potentially consequential operations, and explains the findings with source locations, evidence, uncertainty, and recommended review steps.

**The inspected PowerShell script is never executed.**

## What works today

The current v0.3 development implementation includes:

- PowerShell parsing using the PowerShell Abstract Syntax Tree (AST).
- Six rule families for selected potentially consequential operations.
- Analysis of real `.ps1` files without executing them.
- Source line, column, and character-offset tracking.
- Parser diagnostics and explicit handling of malformed scripts.
- Evidence-backed findings with uncertainty and limitations.
- Structured JSON report export.
- Optional CI/CD exit codes for automated review gates.
- Automated tests covering detection, integration, CLI behavior, desktop support code, and non-execution.
- A native Windows desktop application built with WinUI 3 and Windows App SDK.
- A file picker, findings review, source-line navigation, and a dedicated read-only source workspace.
- A native JSON Save dialog using the same report serializer as the CLI.
- Windows GitHub Actions jobs for CLI/tests and desktop compilation.

The CLI and desktop application both use the same static analysis engine. The desktop is a **v0.3 development preview**, not a signed or packaged release. Local verification currently includes **176 passing automated tests** and a successful Windows CI run with both jobs green.

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

## Windows desktop preview (v0.3)

The native WinUI 3 desktop application is built separately from `BombSquad.slnx`. On Windows, build and launch it with:

```powershell
dotnet build .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug
dotnet run --project .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug
```

Use **Open .ps1 file** to choose a local PowerShell script for read-only AST inspection. **Try sample** loads the included six-family demonstration. The review workspace displays findings, supporting evidence, potential effects, limitations, and source locations. **Inspect source** opens a dedicated, line-numbered source viewer focused on the selected finding; **Back to findings** returns to the review workspace.

Use **Export report** to save the current analysis as JSON through the native Windows Save dialog. The desktop uses the shared JSON schema; Windows asks for confirmation before an existing file is replaced. Cancelling an Open or Save dialog leaves the current analysis intact.

Valid scripts with zero supported matches explicitly say **no matching findings**, not *safe*. For malformed scripts, the interface shows parser diagnostics and identifies that the detection rules were skipped. The inspected `.ps1` source is **never executed**.

At this stage the repository does not provide a signed installer or a verified clean-machine distribution package. Desktop compilation is checked in Windows CI; GUI interactions were verified locally.

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

The **176 passing automated tests** cover positive detections, nonmatching commands, parser errors, file decoding and limits, source line mapping, report generation, CLI input validation, and checks that inspected PowerShell source does not execute.

Build the desktop separately with the Debug command in the Windows desktop section. `.github/workflows/windows-ci.yml` has separate jobs for the CLI/test solution and WinUI desktop compilation. GitHub Actions run #29 passed both jobs on `feat/v03-desktop`; this verifies compilation, not interactive GUI functionality.

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
- [ ] v0.3 - Final documentation, PR review, and merge into `main`
- [ ] Future - Parser diagnostic navigation, app icon, accessibility/resizing review, and additional detection hardening
- [ ] Future - Signed installer, clean-machine testing, and release distribution

See [development progress](docs/progress.md) and the architecture decision records in [docs/adr](docs/adr).

## Technology

C# | .NET 10 | PowerShell AST | WinUI 3 | Windows App SDK | xUnit | Git | GitHub Actions

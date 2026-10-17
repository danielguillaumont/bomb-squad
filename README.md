# BOMB SQUAD

**Know what a script could change before I run it.**

BOMB SQUAD is an offline-first, read-only PowerShell Change & Risk Inspector built with C# and .NET 10.

I built it around a simple problem: PowerShell scripts can modify files, security settings, registry values, accounts, and system services. Before running an unfamiliar script, I want to understand the changes it might attempt.

BOMB SQUAD statically analyzes PowerShell source code, identifies supported potentially consequential operations, and explains the findings with source locations, evidence, uncertainty, and recommended review steps.

**The inspected PowerShell script is never executed.**

## What works today

The current v0.2 development implementation includes:

- PowerShell parsing using the PowerShell Abstract Syntax Tree (AST).
- Six rule families for selected potentially consequential operations.
- Analysis of real `.ps1` files without executing them.
- Source line, column, and character-offset tracking.
- Parser diagnostics and explicit handling of malformed scripts.
- Evidence-backed findings with uncertainty and limitations.
- Structured JSON report export.
- Optional CI/CD exit codes for automated review gates.
- Automated tests covering detection, integration, CLI behavior, and non-execution.

The application currently runs through a command-line interface. A Windows desktop UI is planned but is not implemented yet.

## Quick start

Requirements:

- .NET 10 SDK
- Windows with a PowerShell-compatible development environment

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

Existing report files are not silently overwritten.

Reports may contain excerpts from the inspected script. Treat them as potentially sensitive.

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

The solution separates parsing, analysis, detection rules, and presentation:

```text
PowerShell .ps1 file
       |
       v
BombSquad.Cli
       |
       v
BombSquad.Analysis
       |
       v
PowerShell AST parser
       |
       v
BombSquad.Rules
       |
       v
Structured findings
       |
       +--> CLI explanations
       |
       +--> JSON reports
       |
       +--> CI/CD exit status
```

### Projects

| Project | Responsibility |
|---|---|
| BombSquad.Core | Shared models, findings, source spans, and contracts |
| BombSquad.Analysis | AST parsing and analysis orchestration |
| BombSquad.Rules | Detection rules and rule evaluation |
| BombSquad.Cli | File inspection, output, JSON reports, and exit codes |
| BombSquad.Tests | Unit, integration, safety, and CLI regression tests |

The analysis engine is independent of the planned desktop interface.

## Testing

Build and run the complete automated test suite:

```powershell
dotnet build .\BombSquad.slnx -c Release
dotnet test .\BombSquad.slnx -c Release --no-build
```

The tests cover positive detections, nonmatching commands, parser errors, report generation, CLI input validation, and checks that inspected PowerShell source does not execute.

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

- [x] v0.1 - PowerShell parsing foundation
- [x] v0.2 development - Six detection families
- [x] Real `.ps1` file inspection
- [x] Structured JSON reporting
- [x] CI-friendly exit codes
- [x] Documentation and CI verification
- [ ] Additional rule coverage and analysis hardening
- [ ] Windows desktop interface using WinUI 3
- [ ] Release packaging and distribution

See [development progress](docs/progress.md) and the architecture decision records in [docs/adr](docs/adr).

## Technology

C# | .NET 10 | PowerShell AST | xUnit | Git | GitHub Actions

Planned desktop technology: WinUI 3 and Windows App SDK.

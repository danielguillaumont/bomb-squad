# BOMB SQUAD

**Know what a PowerShell script might change before you run it.**

[![Windows CI](https://github.com/danielguillaumont/bomb-squad/actions/workflows/windows-ci.yml/badge.svg)](https://github.com/danielguillaumont/bomb-squad/actions/workflows/windows-ci.yml)
[![Windows Distribution Preview](https://github.com/danielguillaumont/bomb-squad/actions/workflows/windows-distribution.yml/badge.svg)](https://github.com/danielguillaumont/bomb-squad/actions/workflows/windows-distribution.yml)
![Status](https://img.shields.io/badge/status-v0.9%20release%20candidate-64748b)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-2563eb)

**BOMB SQUAD** is an offline-first, read-only **PowerShell Change & Risk Inspector** built with **C# / .NET 10**, the PowerShell **Abstract Syntax Tree (AST)**, and **WinUI 3**. It helps security-minded developers, administrators, and reviewers understand potentially consequential operations in a script *before* deciding whether to run it.

It identifies selected patterns involving files, Defender settings, registry values, local identities, services and scheduled tasks, and dynamic execution. Each finding includes source evidence, location, potential effects, limitations, and a suggested review step.

> **Safety boundary:** BOMB SQUAD parses inspected PowerShell as text. **It never executes the script being inspected.** Findings are indicators for human review, not confirmation of execution, and **no findings does not mean safe**.

## Project status

| Area | v0.9 development status |
| --- | --- |
| Static PowerShell inspection | Implemented — six detection rule families |
| Windows desktop | Native WinUI 3 development preview |
| CLI and structured JSON | Implemented, with optional CI exit-code gates |
| Multi-file inspection | Implemented for explicitly selected `.ps1` files |
| Baseline comparison | Implemented for two saved batch JSON snapshots |
| Pasted PowerShell snippets | Implemented with bounded, in-memory input |
| Automated regression suite | **317 tests passing** locally on the v0.9 branch |
| Windows build and distribution CI | Previously passed; final v0.9 CI re-verification pending |
| Public signed release / installer | **Not yet available** |
| Clean-machine compatibility | **Not yet verified**; required before v1.0 |

**v0.8 is merged into `main`** through [PR #9](https://github.com/danielguillaumont/bomb-squad/pull/9). The `feat/v09-release-candidate` branch contains the v0.9 development release candidate, which has not yet merged into `main`. The distribution remains an **unsigned development preview**, not a production installer or published GitHub Release.

## What you can do

### Inspect before execution

- Open a local `.ps1` file or paste a PowerShell snippet directly into the desktop app.
- Parse source into PowerShell AST command nodes without executing it.
- Review evidence-backed findings with source line and column navigation.
- Inspect syntax diagnostics. When parsing fails, detection rules are skipped instead of presenting an unreliable clean result.
- See explicit uncertainty notes for function definitions, command shadowing, and unresolved external or qualified command targets.

### Inspect multiple scripts

- Select several `.ps1` files and inspect them independently.
- Continue analysis of other files when an individual script has a parser error.
- Review each file's findings and diagnostics, then export one combined batch JSON report.
- Only explicitly selected files are read; directories are not recursively scanned.

### Compare two inspections

- Compare previously saved **baseline** and **current** batch JSON reports — the original `.ps1` files are not reopened.
- Distinguish **newly detected**, **still detected**, and **no longer detected** pattern matches.
- Identify incomplete or indeterminate comparisons instead of silently treating missing coverage as improvement.
- Export comparison JSON or use `--fail-on-new` in a CI workflow.

### Build and review locally

- Use a native Windows UI for interactive examination, or the CLI for repeatable checks and automation.
- Export machine-readable reports with explicit parse status, evidence, limitations, and non-execution metadata.
- Run without cloud accounts, AI APIs, or network-based script execution.

## Quick start (from source)

**Prerequisites:** .NET 10 SDK. The desktop app additionally requires Windows with the WinUI 3 / Windows App SDK development prerequisites. Windows 11 is the development environment used for local verification.

```powershell
# Clone the project.
git clone https://github.com/danielguillaumont/bomb-squad.git
cd bomb-squad

# Build and test the CLI / analysis solution.
dotnet build .\BombSquad.slnx -c Release
dotnet test .\BombSquad.slnx -c Release --no-build

# Run the built-in CLI demonstration.
dotnet run --project .\src\BombSquad.Cli\BombSquad.Cli.csproj -c Release

# Inspect the included PowerShell sample as TEXT — not by executing it.
dotnet run --project .\src\BombSquad.Cli\BombSquad.Cli.csproj -c Release -- --file ".\samples\example.ps1"
```

The sample illustrates the six implemented detection families. To inspect your own `.ps1`, replace the sample path with an explicitly chosen script path.

### Launch the desktop development preview

The desktop project is built separately from `BombSquad.slnx`:

```powershell
dotnet build .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug
dotnet run --project .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug
```

Use **Open .ps1 file**, **Paste PowerShell snippet**, **Open batch of .ps1 files**, or **Compare inspection reports**. **Try sample** opens an included demonstration. The evidence view explains potential effects and limits; **View source** provides read-only navigation. JSON export uses native Windows Save dialogs.

Pasted snippets are limited to **1 MiB of UTF-8 text**. They are analyzed locally without creating or running a `.ps1` file; source evidence may be included if you explicitly export a report.

## Detection coverage

The current rule set is intentionally **limited and explainable**, not a full PowerShell behavioral model.

| Rule ID | Family | Example pattern |
| --- | --- | --- |
| `BS-FS-001` | Filesystem | `Remove-Item` |
| `BS-SS-001` | Security settings | `Set-MpPreference` |
| `BS-RG-001` | Registry | `Set-ItemProperty` with a literal registry path |
| `BS-ID-001` | Local identity | `Add-LocalGroupMember` |
| `BS-TS-001` | Tasks and services | `Register-ScheduledTask`, `New-Service`, `Set-Service` |
| `BS-DE-001` | Dynamic execution | `Invoke-Expression`, `iex`, expression-based invocation |

A matched command **might** perform a consequential operation if invoked in a particular environment. BOMB SQUAD does not establish runtime control flow, parameter binding, target providers, dynamic values, external executable behavior, or all effects of custom functions. Function definitions are not proof of invocation; unresolved targets and shadowed command names need separate review.

## CLI workflows

### Export a single-file report

```powershell
$cli = ".\src\BombSquad.Cli\BombSquad.Cli.csproj"

# Pick an output filename that does not already exist.
dotnet run --project $cli -c Release -- --file ".\samples\example.ps1" --json ".\inspection.json"
```

The CLI deliberately refuses to overwrite existing JSON report files. Reports can contain sensitive source excerpts and absolute local paths; review them before sharing.

### Inspect multiple files

```powershell
dotnet run --project $cli -c Release -- --batch ".\samples\example.ps1" ".\path\to\another.ps1" --json ".\batch.json"
```

Replace the second placeholder with an **existing** `.ps1` path on your machine. File identities and coverage are recorded independently; inspecting a batch does not scan a whole directory.

### Compare baseline and current batch reports

```powershell
# First generate baseline.json and current.json at DIFFERENT points in time.
# Then compare the saved snapshots (original PowerShell is not reopened).
dotnet run --project $cli -c Release -- --compare ".\baseline.json" ".\current.json" --json ".\comparison.json" --fail-on-new
```

A comparison matches **rule ID plus exact source evidence**, not line numbers. Edits to evidence can appear as a removed and a new match, and moved/renamed file paths are not linked automatically. Parser failures, missing coverage, or incompatible report versions can make a comparison indeterminate.

### Optional automated review gates

| CLI flag | Exit code | Meaning |
| --- | --- | --- |
| `--fail-on-findings` | `0` / `1` | Completed with no supported matches / at least one match |
| `--fail-on-findings` | `2` / `3` | Input or report error / parser errors prevented rule evaluation |
| `--fail-on-new` | `0` / `1` | Complete comparison with no new matches / new matches detected |
| `--fail-on-new` | `2` / `3` | Input or export error / incomplete comparison coverage |

These values describe the **strict-mode flags**. Without them, a completed inspection or comparison may exit `0` even with findings. **Exit code `0` never certifies that the script is safe.**

## v0.9 release candidate

The `feat/v09-release-candidate` branch is undergoing final development release-candidate verification. This is not a public or signed release.

- 317 automated .NET tests passed locally.
- Windows Desktop Debug build and targeted CLI checks passed.
- ZIP entry preflight rejects unsafe archive structures before extraction; extracted-file SHA-256 verification remains required.
- Desktop JSON exports validate serialized content and read the saved file back for verification.
- The desktop displays `v0.9 release candidate`. Engine and rule-set identifiers remain `0.2.0-dev` for comparison compatibility.
- Final hosted CI, distribution artifact review, and pull-request review remain outstanding.

See the [v0.9 closeout checklist](docs/v09-closeout-checklist.md), [release-candidate gates](docs/v09-release-candidate-gates.md), and [ZIP preflight notes](docs/v09-slice2-zip-preflight.md).

A fresh non-administrative Windows x64 machine without the SDK has not been verified. The preview is unsigned. Reports may expose local file paths and source evidence. Comparisons require compatible snapshots with matching file identities. No findings does not establish safety.

## Windows x64 distribution preview (v0.8)

v0.8 establishes a **reproducible preview packaging pipeline** for a self-contained, unpackaged Windows x64 application:

- Locked NuGet dependency restores and pinned Windows dependencies.
- A publish probe that validates required physical branding assets.
- A preview ZIP with a file-by-file SHA-256 integrity manifest and `SHA256SUMS.txt`.
- An independent extraction and verification script.
- GitHub Actions automation that publishes an **expiring workflow artifact**, not a public installer.

At closeout, the development and GitHub build validation covered **558 published files**. The ZIP was verified, and the extracted application was launched and sampled on the developer's Windows PC.

**Not yet verified:** a clean Windows x64 installation with no SDK or development tools, code signing, installer behavior, and production release suitability. Integrity checks do not prove publisher authenticity. **Do not treat the ZIP as a signed or production-ready release.**

For exact preview instructions, see [ZIP distribution](docs/v08-zip-distribution.md), [Windows CI and clean-machine QA](docs/v08-ci-and-clean-machine-test.md), and the [v0.8 closeout checklist](docs/v08-closeout-checklist.md). The workflow is under [GitHub Actions](https://github.com/danielguillaumont/bomb-squad/actions/workflows/windows-distribution.yml).

## Architecture

```text
                PowerShell source / pasted snippet
                               |
                               v
                   PowerShell AST parser
                     + syntax diagnostics
                               |
                               v
                Shared analysis + rule engine
                       (six families)
                               |
                               v
                Evidence-backed findings
                        /           \
                       v             v
              CLI / automation   WinUI 3 desktop
                        \           /
                         v         v
                   Shared JSON reporting
                               |
                  Saved batch report snapshots
                               |
                               v
                   Baseline comparison
                    (CLI + WinUI)
```

| Project | Responsibility |
| --- | --- |
| `BombSquad.Core` | Shared models, evidence spans, diagnostics, and contracts |
| `BombSquad.Analysis` | AST parsing, safe input handling, orchestration, reports, comparison |
| `BombSquad.Rules` | Supported static rule families |
| `BombSquad.Cli` | Console workflows, JSON output, optional CI exit codes |
| `BombSquad.Desktop` | Native WinUI 3 examination workspace, file pickers, source navigation |
| `BombSquad.Tests` | Unit, integration, regression, safety and acceptance testing |

## Quality and security boundaries

At v0.8 closeout:

- **303 automated tests** passed on the merged codebase.
- The .NET 10 test/CLI and WinUI desktop builds passed.
- Windows packaging, ZIP integrity, and workflow artifact checks passed.
- GUI workflows were exercised on the development host; full clean-machine validation is still outstanding.

BOMB SQUAD is **not** an antivirus engine, execution sandbox, malware verdict system, comprehensive PowerShell analyzer, or substitute for manual review. Static findings describe candidate operations; they do not prove that a command will execute or that a target machine will be changed. No matching rules is **not a safety verdict**.

## Roadmap to v1.0

| Milestone | Outcome | Status |
| --- | --- | --- |
| v0.1–v0.4 | Parser, six detection families, WinUI desktop, diagnostics, evidence navigation | Complete |
| v0.5 | Batch inspection of selected scripts | Complete |
| v0.6 | Baseline JSON comparison in CLI and desktop | Complete |
| v0.7 | Pasted inspection, uncertainty handling, acceptance checks | Complete |
| **v0.8** | **Windows preview ZIP, dependency locking, build/distribution CI** | **Complete — merged via PR #9** |
| **v0.9** | **Release gates, ZIP preflight, desktop export verification, CLI and UI QA** | **Final closeout in progress; not yet merged** |
| v1.0 | Final user documentation, release validation, version/tag, signed installer decision | Planned |

The v1.0 scope prioritizes **reliability and honest reporting** over claiming comprehensive PowerShell coverage. For engineering notes, see [development progress](docs/progress.md), [v0.7 acceptance audit](docs/v07-acceptance-audit.md), and architecture decisions in [`docs/adr`](docs/adr).

**Stack:** C# · .NET 10 · PowerShell AST · WinUI 3 · Windows App SDK · xUnit · GitHub Actions

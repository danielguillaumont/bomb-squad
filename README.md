# BOMB SQUAD

Know what a script could change before I run it.

BOMB SQUAD is an offline-first, read-only PowerShell change
and risk inspector for Windows.

The application will inspect PowerShell source, identify
supported potential side effects, and link explanations
to exact source locations.

## Core principles

- Parse PowerShell as text. Never execute imported scripts.
- Explain potential effects, not guaranteed runtime outcomes.
- Show evidence, uncertainty and analysis limitations.
- Keep the C# analysis engine independent of the Windows UI.
- Run locally without accounts, cloud services or AI APIs.

## Planned technology

- C# and .NET 10
- System.Management.Automation PowerShell parser
- WinUI 3 and Windows App SDK
- xUnit testing
- GitHub Actions CI

## Current status

v0.0 Foundation: core contracts, project architecture and automated tests implemented.
The CLI and placeholder analyzer are connected. PowerShell parsing and detection rules are not yet implemented in the permanent application.

See docs/progress.md for the current milestone.

## Non-goals

BOMB SQUAD is not an antivirus engine, malware sandbox,
PowerShell execution environment or universal safety checker.

A result with no supported findings does not prove a script
is safe.

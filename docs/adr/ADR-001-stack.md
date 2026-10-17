# ADR-001 - Technical Stack

Status: Accepted for initial implementation
Date: 2026-10-16

## Context
I need a Windows security utility with a testable,
read-only PowerShell analysis engine.

## Decision
- Use C# and .NET 10 LTS.
- Use System.Management.Automation 7.6.7 for AST parsing.
- Use Parser.ParseInput without PowerShell execution APIs.
- Keep the analyzer independent of the desktop interface.
- Use xUnit for deterministic automated testing.

## Validation
- .NET SDK 10.0.204 worked.
- PowerShell parser proof built successfully.
- Three commands were extracted with original source locations.
- Malformed PowerShell returned diagnostics without crashing.
- Test marker files were not created.
- The proof directly references patched
  System.Security.Cryptography.Pkcs 10.0.13.

## Alternatives
Regex-only scanning and runtime PowerShell evaluation.

## Trade-offs
Static analysis cannot establish every runtime effect.
Parser dependencies must be reviewed and maintained.

## Revisit when
Parser compatibility, licensing, dependency advisories
or target-framework support changes.

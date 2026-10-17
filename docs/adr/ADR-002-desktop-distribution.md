# ADR-002 - Desktop UI and Distribution

Status: Provisional - local feasibility validated
Date: 2026-10-16

## Context
I want a polished, native Windows inspection workstation.

## Decision
Use WinUI 3 with Windows App SDK for the desktop UI.
Keep WPF as a documented fallback if later packaging
or maintenance requirements make WinUI impractical.

## Validation
- Windows 11 Home x64 development machine.
- Developer Mode enabled.
- WinUI template installed using the .NET CLI.
- The template package reported version 0.0.7-alpha.
- DesktopProof built using .NET 10 and win-x64.
- A native WinUI window launched successfully.
- Self-contained, unpackaged Release publishing succeeded.
- The published DesktopProof.exe launched directly.

## Outstanding concerns
- Two IL2104 trimming warnings appeared during publishing.
- The published folder contains numerous dependency files.
- Clean-machine distribution has not been verified.
- Windows App SDK 2.5.1 verified through NuGet package inspection.
- Production template and dependency support require review.

## Alternatives
WPF and a web-based desktop shell.

## Trade-offs
WinUI provides modern native UI capabilities but introduces
Windows App SDK packaging and distribution complexity.

## Revisit when
Clean-machine deployment fails or maintenance becomes
disproportionately difficult.

# BOMB SQUAD - Precision Desk (v0.3 desktop design system)

**Status:** Implemented native WinUI 3 desktop preview, visually reviewed on Windows 11, and locally compiled. The separate WinUI job passed in Windows CI run #29 on 2026-10-17.

**Product:** Offline-first, read-only PowerShell Change & Risk Inspector.

**Audience:** Security engineers, systems administrators, DevOps engineers, and developers reviewing unfamiliar PowerShell.

## Design thesis

I want BOMB SQUAD to feel like a dependable source-inspection workbench, not a SOC monitoring dashboard or a novelty industrial poster. The source evidence is the product: information hierarchy and a neutral technical surface should do more work than decorations.

**Precision Desk** uses a restrained copper accent, cool neutral surfaces, graphite source panes, Windows-native controls, and a clear distinction between *potential behavior* and *confirmed execution*. The app is not a safety-verdict engine.

## Visual tokens

| Purpose | Token |
|---|---|
| Workspace background | `#F2F4F2` |
| Panels | `#FFFFFF` |
| Panel borders | `#DCE2DD` |
| Heading ink | `#20292D` |
| Technical graphite | `#253138` |
| Source viewer | `#222E34` |
| Main copy | `#29373B` |
| Secondary copy | `#687671` |
| Actions and source markers | `#C5533F` |
| Accent on graphite | `#F2B59E` |
| Factual local/static indicator | `#45765E` |
| Pale status background | `#EFF6F1` |

Copper is **not** a malware verdict, risk score, or severity rating. We must not invent numerical risk percentages or label a script safe because no rules matched.

## Typography

- **Bahnschrift**: wordmark, main headings, and prominent numeric counts.
- **Segoe UI**: controls, findings list, explanations, and normal body copy.
- **Consolas**: original script text, filenames, rule IDs, source locations, and status metadata.
- Prefer clear sentence-case copy with small uppercase labels only when helpful for scanning.
- Preserve source whitespace and line numbering; never reformat imported PowerShell for display.

## Current screen architecture

The v0.3 shell has a persistent product header, a central workspace, and a persistent parse/non-execution footer. It contains **two distinct workspaces** rather than stacking multiple nested source scrollers in a single dashboard.

### 1. Findings review workspace

- Primary actions: **Open .ps1 file**, **Try sample**, **Export report**, and **View source**.
- Current source strip identifies the file and labels analysis as read-only.
- One compact metric strip shows AST command nodes, findings for review, and parser diagnostics.
- Two-column content displays the findings register and selected evidence/details.
- **Inspect source** opens Source Focus at the selected finding's original source line.
- Evidence details include source location, potential effect, known limitations, and a recommended next step.

### 2. Source Focus workspace

- Dedicated, large, read-only source pane with numbered original lines.
- Opening it from a finding selects and highlights the corresponding source line.
- **Back to findings** returns to the review workspace.
- Source view also supports clean and malformed scripts even if there are no findings.
- Avoid competing parent/child scroll regions; scrolling should be straightforward with mouse, trackpad, and keyboard.

## Analysis and interaction states

| State | Required behavior |
|---|---|
| No script loaded | Display no source and disabled export/source actions until an analysis exists |
| Built-in or real valid sample | Display supported conditional findings with exact source locations and selectable evidence |
| Valid file without rule matches | Say no supported matches; do **not** declare the script safe |
| Malformed PowerShell | Show parser diagnostic details; make clear that detection rules were skipped |
| File read error | Explain invalid extension, oversized input, decoding failure, or missing path without executing source |
| Open/Save picker cancelled | Keep the previous analysis unchanged |
| JSON exported | Use the shared CLI/desktop report schema; do not imply the source was executed |

The analyst should always know the difference between *what source text contains*, *what our current rules detected*, and *what cannot be established by static inspection*.

## Implementation boundaries

- UI: `src/BombSquad.Desktop/MainPage.xaml` and `MainPage.xaml.cs`; native WinUI 3 and Windows App SDK.
- Analysis: `BombSquad.Analysis` parses PowerShell AST and preserves source location/diagnostics.
- Rules: `BombSquad.Rules` owns the six supported detection families.
- Data loading: shared safe read-only `.ps1` loader with encoding and size checks.
- Source mapping: shared line-oriented source-document component; no PowerShell invocation.
- Reporting: shared JSON serializer reused by `BombSquad.Cli` and `BombSquad.Desktop`.
- Windows CI has two separate jobs. The existing `.slnx` intentionally excludes the WinUI desktop project; the desktop has an independent compile job.

## Verified v0.3 checkpoint

- Local native Debug build succeeded, and all **176 automated tests** passed.
- Windows CI run #29 (`d15ad95`) passed both hosted jobs: solution build/test and desktop compilation.
- Manually inspected `samples/example.ps1`: six commands, six conditional findings, zero parser errors.
- Verified clean script with no findings and malformed script with one diagnostic and skipped rules.
- Verified Source Focus navigation to original lines 10 and 11 and return to findings.
- Verified JSON export using shared schema for valid and malformed inputs and Save dialog cancellation.
- Source was treated as data throughout; no inspected script was executed.

## Deferred quality work

- Formal keyboard-only / screen-reader review, minimum-window-width and scaling test matrix.
- Product application icon and branded package assets.
- Diagnostic-to-source navigation.
- Signed installer, release publishing, and clean-machine usability testing.

These are future engineering tasks, not evidence that v0.3 desktop compilation or manual flow verification failed.

## Public design references (conceptual only)

- [Anthropic frontend-design skill](https://github.com/anthropics/skills/blob/main/skills/frontend-design/SKILL.md)
- [Microsoft frontend-design-review skill](https://github.com/microsoft/skills/blob/main/.github/skills/frontend-design-review/SKILL.md)
- [Microsoft WinUI 3 Gallery](https://github.com/microsoft/WinUI-Gallery)
- [Microsoft PowerToys](https://github.com/microsoft/PowerToys)
- [Microsoft Windows design guidelines](https://learn.microsoft.com/en-us/windows/apps/design/guidelines-overview)
- [Microsoft Windows typography](https://learn.microsoft.com/en-us/windows/apps/design/signature-experiences/typography)

References inspired the usability direction, not copied styling, code, or assets.

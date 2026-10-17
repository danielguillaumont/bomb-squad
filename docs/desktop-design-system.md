# BOMB SQUAD — Precision Desk (design system v0.3B)

**Status:** visual implementation candidate. Requires WinUI compilation and a real Windows-screen review before committing.  
**Product:** offline-first, static-only PowerShell Change & Risk Inspector.  
**Audience:** security engineers, system administrators, DevOps engineers, and developers evaluating unfamiliar PowerShell.

## Design thesis

BOMB SQUAD should feel like a *reliable technical inspection tool* rather than a security-monitoring dashboard, a novelty industrial poster, or a classroom demo. It is an instrument for reviewing source evidence, **not** a verdict engine.

Design identity: **Precision Desk** — contemporary engineering software with restrained color, structured information density, clear typography, an always-visible status line, and a legible evidence pane. Keep the horizontal document/workbench model that distinguishes it from Case Zero, while making it quieter and more professional.

### What changed from Field Dossier v1

| Issue observed in screenshot | Precision Desk treatment |
|---|---|
| Giant black masthead consumed screen height | Compact 74–80px Windows-style application header |
| Large institutional labels and fictional 'instrument 003' | Actual product name, supported engine facts, clear states |
| Warm paper + red read as a concept poster | Neutral-cool surfaces, restrained copper signal, graphite technical area |
| Excessive 10px monospace everywhere | Minimum 12px UI labels, 13–15px readable details, monospace reserved for source and identifiers |
| Bright red evidence-panel header dominated content | White examination pane with a focused, graphite code evidence window |
| Tall stacked blocks pushed results below the fold | Denser source intake, consolidated measurement strip, register/evidence priority |
| Bottom legal reminder required scrolling | Persistent footer with analysis status and non-execution disclosure |
| Decorative '+' icon appeared beside every finding | Clean indexed evidence rows and native selection control |

## Core tokens

| Purpose | Token |
|---|---|
| Application work surface | `#F2F4F2` |
| White surfaces | `#FFFFFF` |
| Panel outlines | `#DCE2DD` |
| Heading ink | `#20292D` |
| Technical graphite | `#253138` |
| Source code surface | `#222E34` |
| Main body text | `#29373B` |
| Secondary text | `#687671` |
| Accent / actions | `#C5533F` |
| Accent on graphite | `#F2B59E` |
| Positive 'static only' state | `#45765E` |
| Pale status background | `#EFF6F1` |

Copper accent indicates a navigational or action emphasis; **not** malware, danger level, or execution certainty. No fabricated risk percentages, severity rankings, or classification scores.

## Type system

- `Bahnschrift` for the restrained wordmark, section titles, and precise large numeric counts.
- `Segoe UI` for all everyday controls, lists, explanations, and prompts; prioritize readability on Windows scaling.
- `Consolas` for PowerShell, filenames, rule IDs, version numbers, and parse status.
- Primary headings 22–28px, operational titles 15px, body 13–14px, supporting labels 12px.
- Sentence case UI strings over decorative uppercase. Use uppercase only for compact instrument-style labels.

## Product hierarchy

1. Persistent identity and factual static-only indicator.
2. Primary action: **Run sample inspection**, until a real file picker exists. No fake Open/Export actions.
3. Current source and source status.
4. A single metrics strip (commands, potential findings, parser diagnostics).
5. A two-column workbench: selectable findings register and selected evidence details.
6. Persistent parsing state and non-execution notice.

### Interaction states

- **Before analysis:** Em dash in counts; current source reads 'No source analyzed'; finding list empty; evidence gives a specific action.
- **After valid sample:** Six commands, six conditional findings, zero parser diagnostics; selecting a record updates source evidence and limitations.
- **After malformed source** (next feature slice): Parser status and diagnostics should be clear; no green safety state; skipped rules explicitly called out.
- **After zero findings** (next feature slice): State what did not match; never call the script safe.
- **Input error** (next feature slice): Explain what failed and how the user can correct it.

## WinUI implementation

- Change only `src/BombSquad.Desktop/MainPage.xaml` in this visual slice. Preserve `MainPage.xaml.cs`, the `AnalysisService` integration, and the twelve named controls used by the existing code-behind.
- Preserve `RunDemo_Click` and `FindingsList_SelectionChanged` exactly.
- Use native WinUI controls, not a WebView or copied HTML/CSS.
- The app shell has three rows: persistent product header, scrollable workspace, persistent status line.
- Constrain independent vertical scrolling to the findings register and evidence panel; the workspace scrolls if windows are small.
- A compact top action area must remain visible at 1280x720. The interface is optimized first for 1440x900 and 1600x900; verify 1920x1080 and DPI scaling.
- Keep keyboard and native screen-reader focus behavior; do not defeat built-in ListView selection or Button semantics.

## Engineering / acceptance checklist

1. Validate XAML parses; all twelve bound names are unique and present.
2. Compile native desktop Debug configuration on Windows.
3. Confirm the packaged WinUI application opens and draws the new appearance.
4. Run demo, verify values **6 / 6 / 0**.
5. Select first and last finding; title, source evidence, potential effect, known limitations and next step update correctly.
6. Confirm result rows can be keyboard-selected.
7. Verify 1280x720, 1600x900, 1920x1080 and 125–150% scale.
8. Run existing 148-test suite; changes must not alter the parser/rules or execute source.
9. Review screenshot before committing. Do not claim Windows compilation has been performed by the packaging environment.

## Research principles and inspiration (not copied code or assets)

- [Anthropic frontend-design skill](https://github.com/anthropics/skills/blob/main/skills/frontend-design/SKILL.md): distinctive point of view, honest copy, restrained attention, full self-critique.
- [Microsoft frontend-design-review skill](https://github.com/microsoft/skills/blob/main/.github/skills/frontend-design-review/SKILL.md): insight-to-action, craft, accessibility, trustworthy feedback.
- [Microsoft WinUI 3 Gallery](https://github.com/microsoft/WinUI-Gallery): native control behavior, layout and accessibility references.
- [Microsoft PowerToys](https://github.com/microsoft/PowerToys): task-focused Windows developer utilities and consistent desktop application architecture.
- [Microsoft Windows design guidelines](https://learn.microsoft.com/en-us/windows/apps/design/guidelines-overview): consistent layout, navigation and usability.
- [Microsoft Windows typography](https://learn.microsoft.com/en-us/windows/apps/design/signature-experiences/typography): readable font sizes, Windows type and UI hierarchy.

All design expression and XAML in this deliverable are newly authored for BOMB SQUAD. We reuse none of the reference repositories' styling source or imagery.

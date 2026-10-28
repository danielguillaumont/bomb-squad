# BOMB SQUAD v0.7 — Final verification checklist

**Starting point:** branch `feat/v07-v1-hardening`, Slice 4 commit `1073a5f`, 297 passing tests and green CI #60. This document is an action checklist, **not evidence that the checks below have already passed**.

## Automated gates (verify before commit)

- [ ] `dotnet test .\BombSquad.slnx -c Release` — expect **303/303** tests, zero failed/skipped.
- [ ] `dotnet build .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug` — succeeds without error.
- [ ] `git diff --check` and `git diff --cached --check` after staging — no whitespace errors.
- [ ] After push, GitHub Actions both Windows jobs green at the Slice 5 commit.

## Manual WinUI checks (record findings before merge)

- [ ] Desktop header displays **v0.7 development**.
- [ ] `Try sample` still shows **6 commands, 6 findings, 0 parser diagnostics**.
- [ ] Pasting `Get-Date`, `Remove-Item -LiteralPath 'demo-cache'`, `Invoke-Expression $dynamicSource` on separate lines shows **3 commands, 2 findings, 0 diagnostics**; export JSON still records `sourceExecuted: false`.
- [ ] Empty paste shows an input error without losing previous analysis.
- [ ] Malformed pasted text displays diagnostics, `Rules skipped: True`, and an incomplete-analysis warning.
- [ ] `reviewer.exe` shows an unresolved-target review note; no safety claim.
- [ ] Previously generated baseline/current batch JSON files compare as before.
- [ ] Navigate the main actions, paste editor, findings list and comparison selectors with **Tab / Shift+Tab / Enter / Space**; verify focus remains visible. Check essential shortcuts (Ctrl+O, Ctrl+D, Ctrl+S, Ctrl+E) in the contexts where enabled.
- [ ] At **100%, 125%, and 150% Windows display scaling** and at narrow and wide window widths, verify no major controls or finding evidence are unreachable or illegible. Record exceptions for v0.8 if necessary.
- [ ] If available, screen-reader spot check: pasted-source edit box has a readable name and help text; inspection status is announced; source-navigation action has a name.

## Scope and release truth

- v0.7 remains a **development preview**; do not represent it as a public signed installer or a completed accessibility certification.
- Malformed scripts still skip all detection rules; earlier parsed commands are not validated as safe.
- Unknown bare executable/module names and runtime command resolution remain unsupported. Static findings and their absence never establish safety or execution.
- Follow-up v0.8: reproducible, dependency-pinned distribution and clean-machine validation; v0.9: full visual/accessibility and portfolio polish; v1.0: tested public release.

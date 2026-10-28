# BOMB SQUAD v0.7 / v1 acceptance-gate audit — first pass

**Baseline:** v0.6 merged at `1093d95`; v0.7 paste-inspection slice at `a6a5142`.

**Purpose:** Reconcile the 15 synthetic acceptance fixtures in Appendix A (page 28) of `BOMB_SQUAD_Master_Build_Plan_v1.0.pdf` against the **current implementation**. This is an engineering gap map, **not** a certification of detection accuracy or product safety. The 12 additional tests in `V07AcceptanceGateAuditTests.cs` provide regression coverage for selected existing behavior. They do not make missing features complete. All PowerShell examples are parsed as source text, never run.

| Gate | Original acceptance intent | Current engineering assessment | Next action |
|---|---|---|---|
| A01 | Commented-out cmdlet produces no operational finding | **Covered** — parser/rules ignore comments and literal text | Keep as negative regression |
| A02 | Literal recursive `Remove-Item`, exact span | **Covered for supported syntax** — filesystem rule matches `Remove-Item` | Keep offset/line evidence checks |
| A03 | Relative/wildcard delete: unresolved destination | **Partial** — finding limitations say path/provider unresolved, but no structured destination resolution | Test wildcard and review phrasing |
| A04 | `New-ScheduledTaskAction` is definition, not registration | **Partial** — no registration false positive, but no explicit definition explanation | Decide whether explicit non-operation context is needed for v1 |
| A05 | `Register-ScheduledTask` registration request | **Covered for supported syntax** — conditional task rule | Extend negative fixtures |
| A06 | Defender preference attempted change, not guaranteed | **Covered for supported syntax** — conditional security-setting rule | Verify opposite-value and false-positive variants |
| A07 | `Invoke-Expression` on variable, runtime contents unknown | **Covered for supported syntax** — dynamic-execution finding | Verify alias and expression variants |
| A08 | Defined function with sensitive body: definition context disclosed | **Improved in Slice 3** — findings in a function body explicitly note that definition does not call the function; invocation/reachability is not resolved | Keep unknown call paths and nested scopes in future audits |
| A09 | Alias/custom-function collision: no unsupported built-in assumption | **Partial, improved in Slice 3** — when a same-named function is declared anywhere in the inspected source, built-in-specific rule findings are conservatively withheld and ambiguity surfaced; lexical scopes, aliases, invocation order and runtime binding are not resolved | Further scope-aware matching and alias review remain future work |
| A10 | Malformed syntax: diagnostics and honest partial findings | **Partial / differs from plan** — diagnostics emitted, but all findings skipped on any syntax error | Decide safe partial-analysis strategy; test explicit status and limitation first |
| A11 | Unknown native executable: unknown behavior visible | **Gap** — ordinary unknown literal command is represented in command list but not explicitly flagged as unknown external behavior | Define UI/model scope and fixture |
| A12 | Unicode/multiline mapping | **Covered for the tested scenario** — parser uses AST spans; CRLF/Unicode regression | Expand malformed multiline + long-line checks |
| A13 | Oversize input rejected gracefully | **Partial** — 1 MiB UTF-8 paste limit covered; file/batch modes need separate audit | Check all input paths and consistent limits |
| A14 | Unsupported module-defined command: unresolved | **Gap** — literal unfamiliar command is not currently systematically described as unresolved module behavior | Add explicit unsupported-command model after scope review |
| A15 | No match: never claims safe | **Covered** — analysis limitations deny safety inference | Audit every UI/CLI/export message |

## Release priorities uncovered

1. **Function-context checkpoint (Slice 3):** A08 and A09 now disclose function-body context and conservatively withhold built-in-specific matches for name collisions. This is **not** reachability analysis or runtime binding resolution; document both residual limitations.
2. **Second:** A10 — decide and test a conservative policy for partial syntax errors. Do not silently change all-errors-skip behavior without protecting the no-execution rule.
3. **Third:** A11/A14 unknown-command visibility and A13 input-limit consistency, followed by scaling, keyboard, and distribution gates.

## Validation instructions

On `feat/v07-v1-hardening` at `a6a5142`, after installing this slice:

```powershell
dotnet test .\BombSquad.slnx -c Release
dotnet build .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug
git status --short
git diff --check
```

Expected: 272 total tests if all 12 added tests pass, and a successful Windows Desktop build. If a new acceptance test fails, **do not weaken the assertion to make it green**; the failure may identify a real coverage gap. Report the exact result.

Keep this audit as a working document. A future v0.7 closeout pass should update each row using real Windows test evidence, not unverified assumptions.

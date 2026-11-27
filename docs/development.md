# Development

## Setup

You need Python 3.12, [uv](https://docs.astral.sh/uv/), and PowerShell: `pwsh` 7, or Windows PowerShell 5.1 on Windows. CI runs on Linux, macOS and Windows with pwsh 7.

```powershell
uv sync --locked --python 3.12
uv run --locked pytest
uv run --locked ruff check .
uvx --from actionlint-py actionlint   # after any workflow change
uv run bombsquad scan samples\example.ps1
```

Set `BOMBSQUAD_POWERSHELL` to pick a specific PowerShell executable.

## Layout

| Path | What it does |
|---|---|
| `src/bombsquad/cli.py` | The `bombsquad scan` and `bombsquad rules` commands |
| `src/bombsquad/scan.py` | Finds files and builds the report |
| `src/bombsquad/inventory.py`, `discovery.py` | Finds entry points and the files they run |
| `src/bombsquad/repo/` | Workflows and actions, editor tasks and dev containers, git hooks, agent files and MCP configs, their rules, and the YAML, JSONC and Markdown readers |
| `src/bombsquad/code/` | The JavaScript, Python and shell analyzers and their rules |
| `src/bombsquad/powershell/dump_ast.ps1` | Parses PowerShell and writes out the syntax tree. It never evaluates input. |
| `src/bombsquad/powershell/parser.py` | Blanks `using` statements, runs the dumper, and reads its output |
| `src/bombsquad/powershell/names.py` | Aliases, native tools, parameter prefixes, registry paths |
| `src/bombsquad/powershell/analyze.py` | Applies the rules and follows decoded content |
| `src/bombsquad/powershell/rules.py` | The rule catalogue |
| `src/bombsquad/registry.py`, `archive.py`, `diff.py`, `source.py` | `bombsquad diff`: registry metadata and hash checks, safe unpacking, the comparison, and the check against the GitHub source and tag record |
| `src/bombsquad/lockfiles.py`, `actionrefs.py`, `gate.py`, `action.yml` | `bombsquad gate`: pinned versions from lockfiles, action references and their review, the pull request report and its comment, and the GitHub Action |
| `src/bombsquad/sarif.py`, `text_report.py` | Output formats |

## Samples that look like malware

Antivirus software quarantines files that contain download cradles, encoded commands or AMSI internals. It also blocks tools from reading output that prints them.

- Test samples like these are stored ROT13-encoded in `tests/test_powershell_rules.py` and decoded in memory.
- Assertions compare rule IDs only, so a failing test does not print a sample.
- Never write such samples to disk in plain text. Never add an antivirus exclusion to make a test pass.

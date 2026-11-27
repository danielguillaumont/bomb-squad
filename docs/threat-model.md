# Threat model

Bomb Squad reads hostile input by design. This document covers what an attacker controls, what they could try, and what stops them. It is updated with each roadmap phase.

## Assets

- **The scanning machine:** a developer workstation or a CI runner, and the credentials on it (cloud keys, tokens, `GITHUB_TOKEN`).
- **The verdict:** a reviewer acting on a report that hides a real finding is the main way Bomb Squad can cause harm.
- **The release:** what users install.

## Attacker-controlled input

The input is the bytes of every scanned file and of pasted text. In later phases it also includes packages, workflow files, and the text an LLM reviewer reads.

## Threats and controls

| Threat | Control | Status |
|---|---|---|
| Input runs during analysis | The PowerShell engine only calls `Parser.ParseInput`. Nothing from the input is evaluated, invoked or imported. Names built from literals are folded by Bomb Squad's own code. | In place |
| Parsing makes the parser open files the input names. `using module` makes the parser read the module to resolve its classes (confirmed on Windows PowerShell 5.1); a network path would open a connection, which is untested. | `using module` and `using assembly` statements are blanked before parsing and reported as BS-DE-005. `tests/test_using_statements.py` proves the parser no longer reads the file. | In place |
| Other parse-time file access, such as DSC `Import-DscResource` in Windows PowerShell 5.1 | Parsing runs in a separate process in an empty temporary directory. | Not yet tested |
| JavaScript, Python or shell input runs during analysis | Parsed with tree-sitter (JavaScript, TypeScript, shell) or Python's `ast`. Nothing is imported, required or evaluated, and npm and pip are never invoked. | In place |
| Following targets and imports reads files outside the scan, such as `node ../../.ssh/x` or a symlink to `~/.aws/credentials` | Targets must resolve inside the package directory and imports inside a scanned directory. Symlinked files are skipped during directory walks. | In place |
| Deeply nested code exhausts the Python stack | `RecursionError` and `MemoryError` from `ast` are caught and reported, and the tree-sitter walks are iterative. Import following stops at five levels and 500 files. | In place |
| A deliberate parse error hides the rest of a file | Rules still run on whatever the parser reads, and parse errors are reported. | In place |
| A huge or deeply nested input exhausts memory or time | Files over 5 MB are skipped and reported. Parsing has a 120-second timeout. Decoding stops at three nested levels, which is reported. Folded strings are capped at 1,000,000 characters. | In place |
| Encoded or obfuscated code hides behaviour | `-EncodedCommand`, `-Command`, base64 literals and literal text passed to `Invoke-Expression` or `[ScriptBlock]::Create` are decoded and analysed. Names built from literals are folded. Text computed at run time is not resolved, and each finding says so. | Partial |
| Terminal escape sequences in evidence | Not yet handled. Evidence is printed as found. | Open |
| The scanner's own dependencies or CI are compromised | The runtime dependencies are tree-sitter and three grammars, which ship native code. They are locked with hashes in `uv.lock`, checked with `uv sync --locked`, and resolved only from releases at least seven days old (`exclude-newer`). Actions are pinned by commit SHA with read-only permissions. | In place |
| Antivirus quarantines test fixtures, breaking checkouts | Fixtures that look like malware are ROT13-encoded in the tests and decoded in memory. | In place |

## Later phases

These get their own rows when they are built:

- **Detonation** (Phase 5): sandbox escape, canary-credential leaks and network egress.
- **The live watch** (Phase 6): false accusations against real packages. Changes are reported, never verdicts, and a person reviews every report.
- **LLM triage** (Phase 7): prompt injection from the code under review. The LLM can reorder findings but never suppress them.

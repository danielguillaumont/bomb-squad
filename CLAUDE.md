# Bomb Squad

Pre-execution review for third-party code. It finds what runs automatically in packages, repositories, workflows, editor and agent configs, and what an update newly gains. Direction: **Bomb Squad 2** (Python 3.12, uv). See `docs/roadmap.md`. v1.0.0, the WinUI PowerShell inspector in C#/.NET, is frozen at its tag and release.

## Evidence rules

These apply to code, docs, site copy, and commit messages.

- Never write a number that was not computed from a pinned, dated dataset or run. No placeholder or "illustrative" statistics.
- Accuracy figures come only from the benchmark. They state their denominators, dataset commits and dates, and the GuardDog result on the same packages.
- Findings are capabilities and changes, not verdicts. Never call a real package or repository malicious unless the registry, OpenSSF malicious-packages or the maintainer has confirmed it, and link the confirmation.
- No findings does not mean safe. Say so wherever results are shown.
- Keep source semantics exact. A registry timestamp is a publish time, not when a compromise began. A write-up date is a disclosure date. Provenance shows where a package was built, not that its code is benign.
- Say what the analysis cannot see: runtime-only behaviour, time-gated or conditional payloads, code fetched after install.

## Safety rules

- Static engines parse input. They never execute, import, install or build it.
- Detonation runs only in a disposable container with no host mounts, canary credentials only, and network limited to the local sink.
- Malware samples, datasets and scan outputs never go into Git (`data/` is gitignored). Benchmarks run on Linux CI, not on a development machine.
- Never report a package to a registry, or publish a flag, without a human review.
- Workflows pin actions by commit SHA, declare least-privilege permissions, and never use `pull_request_target` with a checkout of PR code.
- The flag log and the defusal record are append-only. Never rewrite, drop or backfill past entries.
- LLM triage is opt-in, sends only flagged hunks, and can reorder findings but never suppress a rule finding.

## Commands

```powershell
uv sync --locked --python 3.12
uv run --locked pytest
uv run --locked ruff check .
uvx --from actionlint-py actionlint   # after any workflow change
uv run bombsquad scan samples\example.ps1
```

Parsing PowerShell needs `pwsh` 7, or Windows PowerShell 5.1 on Windows. See `docs/development.md`.

Antivirus quarantines files that spell out download cradles, encoded commands or AMSI internals, and blocks reading tool output that prints them. Keep such samples ROT13-encoded in tests, compare rule IDs only in assertions, and never print or write them in plain text.

## Conventions

- Conventional commit subjects (`feat:`, `fix:`, `chore:`, `docs:`), one PR per roadmap step.
- Plain names for files and docs. No milestone or ticket codes in file names.
- Docs stay short. Update the existing ones instead of adding per-change write-ups.

# BOMB SQUAD

**Find what runs before anyone chooses to run it.**

Bomb Squad reviews third-party code before it runs. Version 2 is being built step by step ([roadmap](docs/roadmap.md)).

It first lists the **entry points**: code that runs without anyone choosing to run it. Today that covers npm install hooks; Python's `.pth` files, `setup.py`, in-tree build backends, `sitecustomize` and `conftest.py`; GitHub Actions workflows and actions; VS Code tasks that run when a folder opens; dev container lifecycle commands; husky, lefthook and pre-commit hooks; and AI coding agents' instruction files, hooks, MCP servers and settings. It then reads the code each entry point reaches and reports what that code could do, with the exact source, how it was reached, and what the analysis could not see. **It never runs anything it scans.**

```text
$ bombsquad scan demo-package
Runs without being asked (1 entry point)
  demo-package/package.json:5  postinstall script
      runs on: npm install, including when installed as a dependency
      runs: node scripts/setup.js
      reaches: demo-package/scripts/setup.js
      reaches: demo-package/scripts/send.js

demo-package/package.json
  5:5  high    BS-EX-001  Collects secrets and can send them out
      node scripts/setup.js
      via: runs on npm install, including when installed as a dependency: postinstall script in demo-package/package.json:5
      via: collects: collects all environment variables at demo-package/scripts/setup.js:2 (JSON.stringify(process.env))
      via: network: opens network connections at demo-package/scripts/send.js:1 (require("https"))
  ...
```

## What it finds

47 rules, listed by `bombsquad rules`.

**In GitHub Actions**, a deliberately narrow set of trust-boundary rules (zizmor is the reference for a full audit):

- `pull_request_target`, `workflow_run` or `issue_comment` workflows that check out the pull request's code;
- issue titles, comment bodies, branch names and other attacker-controlled text expanded into `run:` or `github-script`;
- secrets sent to the network from a step, the shape of the GhostAction workflows;
- `write-all` or missing token permissions, `id-token: write`, and self-hosted runners;
- third-party actions, reusable workflows, images and hook repositories referenced by a tag or branch instead of a commit SHA.

**In editor and hook configuration:** VS Code tasks that run when the folder opens, dev container commands that run on the host, and git hooks, with their commands analysed like any other entry point.

**In AI coding agents' files** (`AGENTS.md`, `CLAUDE.md`, Copilot and Cursor rules, skills, slash commands, `.claude/settings.json`, `.mcp.json` and other MCP configs):

- instructions to skip confirmation, to hide actions from the user or ignore other instructions, to read credentials, or to fetch from or send to a URL, with stronger findings when they hide in an HTML comment or invisible Unicode tags;
- the code blocks in those files, analysed like any other code;
- hooks, status lines, credential helpers and `` !`command` `` lines that run shell commands on agent events;
- settings that approve tool calls, shell commands, MCP servers or automatic tasks in advance, redirect the agent's API traffic, or make programs load code through `NODE_OPTIONS`, `LD_PRELOAD` and similar;
- MCP servers launched through `npx`, `uvx` or `docker run` without a pinned version, and the archived reference servers.

**In code an entry point reaches** (JavaScript and TypeScript, Python, shell, and code embedded with `node -e`, `python -c`, `sh -c` or a PowerShell command line, including workflow `run:` steps):

- network access, and downloads piped into a shell;
- credential files and token variables (`~/.npmrc`, `~/.aws/credentials`, `GITHUB_TOKEN`), and code that collects the whole environment;
- both of those reachable from one entry point, reported once at the entry point as **BS-EX-001**;
- text evaluated as code, and decoded data that is then run;
- packed or obfuscated code, and other programs started.

**In any text file:** invisible or direction-changing Unicode (Trojan Source and similar), and code hidden after a long run of whitespace.

**In PowerShell**, wherever it is (the language of most paste-and-run attacks, read with PowerShell's own parser):

- deletion, registry and autostart writes, accounts, scheduled tasks and services;
- Defender settings and exclusions, and AMSI or script-logging tampering;
- downloads, and downloads that are run, including through a variable;
- `Invoke-Expression`, script blocks, compiled C#, assemblies and modules loaded from a path;
- `-EncodedCommand`, `-Command` text and base64 literals, decoded and analysed;
- names assembled from string literals, aliases, native tools, and en and em dashes in place of `-`.

Every finding carries its source location, the evidence, how it was reached and what the analysis could not see. **No findings does not mean safe.**

## How accurate it is

Measured against GuardDog 3.2.0 on the same packages, in a held-out run on 2026-11-27 whose protocol was fixed before it ran. The packages were 200 npm and 200 PyPI samples from the DataDog malicious-software-packages-dataset at commit `72c723be5470` (2026-11-05), and 200 npm and 197 PyPI releases of popular packages. None of them was used while the rules were tuned. Bomb Squad's figures are at a review or high finding; GuardDog's are at its `suspicious` or `high_risk` label.

| | Malicious found, Bomb Squad | Malicious found, GuardDog | Popular releases flagged, Bomb Squad | Popular releases flagged, GuardDog |
|---|---|---|---|---|
| npm | 53.0% (106/200) | 70.0% (140/200) | 3.0% (6/200) | 0.5% (1/200) |
| PyPI | 71.5% (143/200) | 88.5% (177/200) | 8.6% (17/197) | 14.7% (29/197) |

GuardDog finds more. Bomb Squad looks only at what runs on install and the code it reaches. It flags none of the 73 npm and 15 PyPI samples where it found no install-time entry point, such as payloads that run on import or require. On npm samples with an install-time entry point, it finds 84.8% (106/125) to GuardDog's 80.8% (101/125). 76 of the PyPI samples share one pattern that both tools catch. Without them, the PyPI figures are 54.0% (67/124) for Bomb Squad and 81.5% (101/124) for GuardDog.

The sample is held out by package, not by campaign: the same PyPI pattern was in the development sample, which shaped the rules. The dataset was mostly found by GuardDog, and there is no after-cutoff measure yet. The [write-up](docs/research/guarddog-benchmark.md) has the full tables for both samples, where Bomb Squad loses, its false positives checked by hand, and the pins.

## Use it

Requires Python 3.12. PowerShell files and command lines also need PowerShell: PowerShell 7 (`pwsh`) on any OS, or Windows PowerShell 5.1.

```powershell
uv tool install git+https://github.com/danielguillaumont/bomb-squad@v2.0.1
bombsquad scan .\some-package               # files or directories
Get-Clipboard | bombsquad scan -             # check a pasted command before running it
bombsquad scan .\unpacked-pkg --package      # as a published package: workflows and hooks in it are info
bombsquad scan . --format sarif -o bombsquad.sarif --fail-on high
bombsquad diff npm:some-package@1.4.2..1.4.3   # what an update newly gains
bombsquad diff pypi:some-package@2.0..2.1 --format json
bombsquad diff npm:some-package@1.4.2..1.4.3 --source --record tags.json
bombsquad diff old.tgz new.tgz                 # two local folders or archives
bombsquad detonate npm:some-package@1.4.3      # Linux with Docker: run it in a sandbox
```

Output is text, JSON or SARIF 2.1.0 (for GitHub code scanning). JSON and SARIF are UTF-8 in a file (`-o`) and ASCII with escapes on standard output, so they stay valid when piped on Windows. `--fail-on high|review|info` sets a non-zero exit code for CI.

`bombsquad diff` downloads both versions from npm or PyPI, checks each against the registry's hash, unpacks them without running anything, and scans both. It reports new and changed entry points, new findings, code files that gained a minified line, and publish signals: a different publisher or maintainers, provenance that went missing, a changed repository, and how recently the new version was published. With `--source` it also compares the new version with its GitHub repository at the release tag, listing files only in the package or changed from the source, and with `--record` it keeps each tag's commit so a tag that later moves is reported.

`bombsquad detonate` is the one command that runs a package, and only inside a throwaway container:
- **Isolation:** no host folders are mounted, and its network reaches only a local sink.
- **Bait:** fake credentials are placed where stealers look.
- **What it records:** which fake credentials were read or sent, network attempts and programs started, set against what the static scan predicted. Something predicted but not observed is not cleared.

It runs only on Linux, and is meant for disposable CI runners ([methodology](docs/methodology.md#detonation)).

### In pull requests

`bombsquad gate` reports what a pull request newly runs: new entry points and findings in the repository, what each dependency version its lockfiles newly pin gains from the registry, and what each updated action gains between its old and new commit. As a GitHub Action:

```yaml
on: pull_request
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: danielguillaumont/bomb-squad@<commit SHA>
        with:
          fail-on: high
```

It writes the report to the job summary and outputs the paths of Markdown, JSON and SARIF files. [`gate.yml`](.github/workflows/gate.yml) shows how to post the Markdown as a comment from a separate job, the only one with write access.

## How it stays safe

Scanning treats the input as data, never code:

- PowerShell is parsed by `Parser.ParseInput` in a separate process, in an empty working directory. `using module` and `using assembly` statements are blanked first, because the parser opens the files they name.
- JavaScript, TypeScript and shell are parsed with tree-sitter, and Python with the standard library's `ast`. Nothing is imported or evaluated.
- YAML is composed into nodes with PyYAML's safe loader and never constructed into objects. VS Code's JSON with comments is read by Bomb Squad's own reader. Markdown is split into prose, code and comments without rendering it.
- Only files inside the scanned directories are followed, and symlinked files are skipped.
- `bombsquad detonate` is the exception, and runs a package only inside a container: no mounts, no capabilities beyond what strace needs, an unprivileged user, and a network that reaches only the sink. See the [threat model](docs/threat-model.md).
- `bombsquad diff` fetches only over HTTPS from the npm and PyPI hosts, and from GitHub with `--source`, refuses artifacts whose hash differs from the registry's, and unpacks only regular files that stay inside a temporary folder.

See the [threat model](docs/threat-model.md) for the rest, and [methodology](docs/methodology.md) for what each rule matches and its limits.

## Version 1

[Bomb Squad v1.0.0](https://github.com/danielguillaumont/bomb-squad/releases/tag/v1.0.0), the WinUI desktop inspector, is frozen at its tag and release.

v1 matched 12 PowerShell command names and `iex` by exact name. The constructs it missed are now regression tests in [`tests/test_powershell_rules.py`](tests/test_powershell_rules.py). Its six-finding sample still produces the same six findings.

**Built with:** Python · PowerShell AST · tree-sitter · PyYAML · pytest · ruff · uv · GitHub Actions. [Development](docs/development.md).

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

Every finding carries its source location, the evidence, how it was reached and what the analysis could not see. Accuracy has not been measured yet. The benchmark against GuardDog is [Phase 4](docs/roadmap.md#phase-4-benchmark-against-guarddog), and until it runs this README states no detection rates. **No findings does not mean safe.**

## Use it

Requires Python 3.12. PowerShell files and command lines also need PowerShell: PowerShell 7 (`pwsh`) on any OS, or Windows PowerShell 5.1.

```powershell
uv tool install git+https://github.com/danielguillaumont/bomb-squad
bombsquad scan .\some-package               # files or directories
Get-Clipboard | bombsquad scan -             # check a pasted command before running it
bombsquad scan . --format sarif -o bombsquad.sarif --fail-on high
bombsquad diff npm:some-package@1.4.2..1.4.3   # what an update newly gains
bombsquad diff pypi:some-package@2.0..2.1 --format json
bombsquad diff old.tgz new.tgz                 # two local folders or archives
```

Output is text, JSON or SARIF 2.1.0 (for GitHub code scanning). `--fail-on high|review|info` sets a non-zero exit code for CI.

`bombsquad diff` downloads both versions from npm or PyPI, checks each against the registry's hash, unpacks them without running anything, and scans both. It reports new and changed entry points, new findings, code files that gained a minified line, and publish signals: a different publisher or maintainers, provenance that went missing, a changed repository, and how recently the new version was published.

## How it stays safe

The input is data, never code:

- PowerShell is parsed by `Parser.ParseInput` in a separate process, in an empty working directory. `using module` and `using assembly` statements are blanked first, because the parser opens the files they name.
- JavaScript, TypeScript and shell are parsed with tree-sitter, and Python with the standard library's `ast`. Nothing is imported or evaluated.
- YAML is composed into nodes with PyYAML's safe loader and never constructed into objects. VS Code's JSON with comments is read by Bomb Squad's own reader. Markdown is split into prose, code and comments without rendering it.
- Only files inside the scanned directories are followed, and symlinked files are skipped.
- `bombsquad diff` fetches only over HTTPS from the npm and PyPI hosts, refuses artifacts whose hash differs from the registry's, and unpacks only regular files that stay inside a temporary folder.

See the [threat model](docs/threat-model.md) for the rest, and [methodology](docs/methodology.md) for what each rule matches and its limits.

## Version 1

[Bomb Squad v1.0.0](https://github.com/danielguillaumont/bomb-squad/releases/tag/v1.0.0), the WinUI desktop inspector, is frozen at its tag and release.

v1 matched 12 PowerShell command names and `iex` by exact name. The constructs it missed are now regression tests in [`tests/test_powershell_rules.py`](tests/test_powershell_rules.py). Its six-finding sample still produces the same six findings.

**Built with:** Python · PowerShell AST · tree-sitter · PyYAML · pytest · ruff · uv · GitHub Actions. [Development](docs/development.md).

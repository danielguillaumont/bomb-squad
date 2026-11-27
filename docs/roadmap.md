# Roadmap: Bomb Squad 2

> Find what runs before anyone chooses to run it.

Bomb Squad v1.0.0 is a Windows desktop inspector for PowerShell scripts. It is frozen at its tag and release. Bomb Squad 2 inspects third-party code (dependencies, workflows, editor and agent configs, scripts) for code that executes automatically on install, build, test, folder open or agent start. It reports what a change newly gains, with source-linked evidence, and its accuracy is measured against GuardDog on a public, time-split benchmark.

## Why

Most of the supply-chain incidents of August–November 2026 did not need anyone to choose to run the attacker's code. Each one used an entry point that runs on its own:

| Incident (date of source) | Entry point | Source |
|---|---|---|
| ChainDrop npm worm (2026-08-04) | `preinstall` hook; plants `.claude/settings.json` and `.vscode/tasks.json` in repos | [Microsoft](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/) |
| Prompt injection against AI coding agents in CI (2026-08-07) | Issue, PR and agent config content read by agents with credentials | [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-coding-agent-ci-prompt-injection-202608/) |
| GhostAction, second wave (2026-10-09) | Workflow files pushed to default branches with stolen tokens | [StepSecurity](https://www.stepsecurity.io/blog/ghostaction-returns) |
| Agent instruction-file poisoning (2026-10-27) | `AGENTS.md`, `CLAUDE.md`, Cursor rules, Copilot instructions | [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-agent-instruction-file-poisoning-20261027/) |
| Deprecated MCP servers installed by agents (2026-11-03) | Unpatched reference MCP servers launched from agent memory | [Help Net Security](https://www.helpnetsecurity.com/2026/11/03/mcphantom-deprecated-mcp-servers/) |
| ClickFix tradecraft (2026-11-10) | Pasted PowerShell that creates scheduled tasks and SSH tunnels | [Huntress](https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix) |
| Microsoft `agent-framework` on PyPI (2026-11-17) | `.pth` file run at every Python start | [StepSecurity](https://www.stepsecurity.io/blog/microsoft-agent-framework-pypi-package-compromised) |
| PolinRider (2026-11-26) | Rewritten commits; `conftest.py`, build configs, VS Code folder-open tasks | [The Hacker News](https://thehackernews.com/2026/11/north-korea-linked-polinrider-poisons.html) |

v1 cannot help with these. It matches 12 PowerShell command names and `iex` by exact name, and flags calls made through an expression (`& (...)`). It does not resolve aliases or native tools (`rm`, `del`, `reg`, `schtasks`, `sc.exe`, `net`), it has not been measured on any real malicious script, and it runs only as a Windows desktop app. The parts worth keeping are its design: parse and never execute, tie every finding to a source span, state each finding's limits, and compare against a baseline.

General SAST, SCA and secrets scanning are well served (Semgrep/Opengrep, CodeQL, OSV-Scanner, Trivy, gitleaks). Bomb Squad 2 stays out of them. The closest open-source tools each cover one surface: GuardDog (packages), zizmor and poutine (workflows), Snyk Agent Scan (agent configs, which needs a Snyk account). Bomb Squad joins the surfaces, diffs versions, and publishes how well it does.

## Principles

- Static engines parse input. They never execute, import, install or build it.
- Detonation runs only in a disposable container with canary credentials and no route to the internet.
- Findings report capabilities and changes, not verdicts. No findings does not mean safe.
- Every finding has a source location, the evidence, what it could do, and what the analysis could not see.
- Accuracy claims come only from the benchmark: time-split, with denominators and dataset dates, against GuardDog on the same packages.
- LLM triage is optional, off by default, and must beat the no-LLM baseline to be used.

## Phase 0: Reset ✅

- **v1 frozen:** v1.0.0 stays at its tag and release. The WinUI app, the C# engine, the packaging scripts and the milestone documents left `main`.
- **Docs:** reduced to the README, this roadmap, `threat-model.md`, `methodology.md` and `development.md`.
- **Package and CI:**
  - A Python 3.12 package and CLI (`bombsquad scan`, `bombsquad rules`), managed with uv, with text, JSON and SARIF 2.1.0 output and `--fail-on` for CI.
  - CI runs on Linux, macOS and Windows with PowerShell 7, and again on Windows with Windows PowerShell 5.1.
  - Actions are pinned by commit SHA with read-only permissions.
- **PowerShell engine:**
  - `Parser.ParseInput` runs in a separate process, and its syntax tree is emitted as JSON.
  - Names resolve through aliases, module-qualified names and native tools (`reg`, `schtasks`, `sc.exe`, `net`, `certutil`, `bitsadmin`).
  - Names and arguments built from string literals are folded.
  - `-EncodedCommand` (including en-dash forms and `Start-Process`), `-Command`, base64 literals and literal text run by `Invoke-Expression` or `[ScriptBlock]::Create` are decoded and analysed.
  - New rules cover download-and-run (inline, piped, or through a variable), Defender exclusions, AMSI and logging tampering, autostart registry keys, compiled C# and loaded assemblies, and modules loaded from a path.
- **Parser safety:** the parser reads the file a `using module` statement names when it resolves classes (tested on Windows PowerShell 5.1), and v1 parsed this way too. Those statements are now blanked before parsing and reported. Rules also run on files with parse errors, so a deliberate error cannot hide the rest of a file. See the [threat model](threat-model.md).

**Exit met:** the constructs v1 missed are regression tests in `tests/test_powershell_rules.py`, and the v1 sample still produces its six findings.

## Phase 1: Inventory, what runs without a decision

`bombsquad scan <path>` lists every automatic-execution entry point and what the code behind it can do. It ships in three steps.

| Surface | Runs on | Files | Step |
|---|---|---|---|
| npm | install | `preinstall`, `install`, `postinstall`, `prepare` scripts and the scripts they call; `binding.gyp` | 1a ✅ |
| Python | install, interpreter start, test | `setup.py`, in-tree build backends, `.pth`, `sitecustomize.py`, `conftest.py` | 1a ✅ |
| Scripts | when called by any of the above | JavaScript, TypeScript, Python, shell, PowerShell | 1a ✅ |
| GitHub Actions | push, PR, schedule | `.github/workflows/*`, composite `action.yml` | 1b ✅ |
| Editors | folder open, container start | `.vscode/tasks.json` (`runOn: folderOpen`), `.devcontainer/*` lifecycle commands | 1b ✅ |
| Git hooks | commit, push | `.husky/`, `lefthook.yml`, `.pre-commit-config.yaml` | 1b ✅ |
| AI agents | agent start, tool call | `AGENTS.md`, `CLAUDE.md`, `.claude/settings.json` hooks, `.cursor/rules`, `.github/copilot-instructions.md`, MCP configs, `SKILL.md`, agent `.env` files | 1c ✅ |

### 1a: npm, Python and the code they run ✅

- **Entry points:**
  - npm install and prepare hooks, including scripts they call with `npm run`;
  - `binding.gyp` when there is no install script, with its `<!(…)` command expansions;
  - `.pth` lines that start with `import`, `setup.py`, in-tree build backends, `sitecustomize`/`usercustomize` and `conftest.py`.
- **Reachability:** from each entry point, the files its command names and their local JavaScript imports (five levels deep), plus code embedded with `node -e`, `python -c`, `sh -c` or a PowerShell command line. Code no entry point reaches is not analysed, except PowerShell and files named on the command line.
- **Analysis:** JavaScript, TypeScript and shell with tree-sitter, Python with the standard library's `ast`. The rules cover:
  - network access, child processes, credential paths and token variables, and whole-environment collection;
  - `eval`, `Function`, `exec`, and decode-then-run code;
  - packed code;
  - hidden Unicode and whitespace padding in any text file.
- **Correlation:** credential or environment collection plus network access reachable from one entry point is reported once at the entry point (BS-EX-001).

**Exit met:** `tests/test_entry_points.py` has fixtures modelled on the `preinstall` stealer, `.pth` and `conftest.py` techniques above, plus negatives (a prebuild-style install that only spawns a build, code no entry point reaches, targets outside the package).

### 1b: workflows, editors and git hooks ✅

- **Entry points:**
  - each GitHub Actions workflow job, and composite, JavaScript and Docker actions in `action.yml`;
  - VS Code tasks with `runOn: folderOpen`, and the tasks they depend on;
  - dev container lifecycle commands, with `initializeCommand` reported because it runs on the host (BS-EP-003);
  - husky hooks, lefthook commands, scripts and jobs, and pre-commit local hooks and remote hook repositories.
- **Workflow rules** were kept narrow, covering only trust-boundary cases that lead to execution or credential exposure:
  - `pull_request_target`, `workflow_run` or `issue_comment` with a checkout or fetch of the pull request's code (BS-GHA-001);
  - attacker-controlled `${{ github.event.* }}` fields expanded into `run:` or `github-script` (BS-GHA-002);
  - `write-all` or missing permissions (BS-GHA-003), and `id-token: write` (BS-GHA-004);
  - self-hosted runners (BS-GHA-005);
  - secrets sent to the network from a step, the GhostAction pattern (BS-GHA-006);
  - third-party actions, reusable workflows, container images, pre-commit repositories and lefthook remotes referenced by tag or branch (BS-PIN-001).

  For a full audit, zizmor is the reference.
- **Analysis:** `run:` steps, task commands, lifecycle commands and hooks go through the 1a analysis in the language of their shell, with findings on the exact line of a `run: |` block. Files they run are followed. A file passed only as data (`cat x.sh`) is no longer a target, for npm scripts too.
- **Parsing:** YAML is composed into nodes and never constructed into objects. VS Code's JSON with comments is read by Bomb Squad's own reader, which keeps positions.

**Exit met:** `tests/test_repo_entry_points.py` has fixtures modelled on GhostAction, ChainDrop and PolinRider, the pull-request trust-boundary cases, and each git hook tool, plus negatives (base-branch `pull_request_target`, values passed through `env:`, header-only deploy tokens, tasks that do not run on open, data-only file arguments). This repository's own workflows produce no findings.

### 1c: agent files and code scanning ✅

- **Entry points:**
  - agent instruction files: `AGENTS.md`, `CLAUDE.md` (with its `@` imports), `GEMINI.md`, Copilot instructions, prompts and agents, Cursor, Windsurf, Cline, Roo Code and Kiro rules, Claude Code commands, subagents and rules, and `SKILL.md`;
  - Claude Code, Cursor and Gemini CLI hooks, Claude Code status lines and credential helpers, plugin hooks, and Codex `notify`;
  - MCP servers in the Claude Code, Cursor, VS Code, Gemini CLI, Codex, opencode, Amazon Q, Roo Code, Kiro and Claude Desktop configurations.
- **Instruction rules** match fixed phrasings clause by clause, and skip clauses that negate them:
  - skipping confirmation, including flags such as `--dangerously-skip-permissions` (BS-AG-001);
  - hiding actions from the user or ignoring other instructions (BS-AG-002);
  - reading credentials (BS-AG-003);
  - fetching from or sending to a URL (BS-AG-004).

  Matches inside HTML comments or invisible Unicode tag characters are reported as high. Code blocks and inline commands go through the 1a analysis at their exact line, and correlation (BS-EX-001) covers instructions to read credentials and send them out.
- **Configuration rules:**
  - commands run on agent events, and `` !`command` `` in commands and skills (BS-AG-005);
  - approvals granted in advance, such as `bypassPermissions`, `enableAllProjectMcpServers` and `chat.tools.autoApprove` (BS-AG-006);
  - agent API traffic sent to another host, or TLS checks turned off (BS-AG-007);
  - code loaded through `NODE_OPTIONS`, `LD_PRELOAD` and similar variables, in settings, MCP server environments and `.env` files (BS-AG-008);
  - MCP servers launched without a pinned version (BS-MCP-001);
  - the archived reference servers listed in modelcontextprotocol/servers-archived (BS-MCP-002).
- **Code scanning:** CI scans this repository and uploads the SARIF to GitHub code scanning from a job that alone has `security-events: write`.
- **Also:** `dict(os.environ)`, `os.environ.copy()` and `{**os.environ}` count as collecting the environment when they are serialised. PowerShell embedded in a workflow, task or agent file is noted as not analysed when no PowerShell is installed, instead of failing the scan.

**Exit (Phase 1) met:** each surface in the table has fixture tests modelled on a public write-up (`tests/test_entry_points.py`, `tests/test_repo_entry_points.py`, `tests/test_agent_entry_points.py`), and SARIF from this repository's CI loads in GitHub code scanning (first analysis on 2026-11-27, from the 1c pull request, with the six findings of `samples/example.ps1`).

## Phase 2: Version diff, what an update newly gains

`bombsquad diff npm:<pkg>@<old>..<new>` (and `pypi:`) fetches both published artifacts from the registry, checks their registry hashes, and never installs them. It ships in two steps.

### 2a: capability diff and publish signals ✅

- **Fetching:** HTTPS only, to `registry.npmjs.org`, `pypi.org` and `files.pythonhosted.org`, redirects included. Each artifact is checked against the registry's SHA-512 (npm) or SHA-256 (PyPI) before it is opened. For PyPI, the sdist and one wheel are compared, because install hooks live in the first and `.pth` files in the second.
- **Unpacking:** regular files only. Links, absolute paths, `..`, drive letters, names Windows cannot hold and case clashes are skipped and listed. Member counts and decompressed bytes are capped.
- **Capability diff:** both versions are scanned as `bombsquad scan` would, and the report lists:
  - new and changed entry points;
  - new findings, matched by rule, file and evidence so moved code is not reported again;
  - added and removed files;
  - code files that gained a line of 1,000 characters or more.
- **Publish signals,** dated by registry timestamps:
  - publisher and maintainer changes (npm; PyPI does not publish uploaders);
  - provenance attestations present on the old version and missing on the new one;
  - a changed declared repository;
  - release age at scan time, flagged inside a seven-day window.
- Two local folders or archives can be compared too: `bombsquad diff old.tgz new.tgz`.

### 2b: artifact against source and history ✅

`bombsquad diff … --source` and `--record FILE`. GitHub repositories only, read over the public API without credentials.

- **Tags:** the new version's tag is looked up under the usual names (`v1.2.3`, `1.2.3`, `name@1.2.3` and others). A missing tag is reported, and so is a tag that does not point at the commit npm recorded at publish time (`gitHead`).
- **Artifact against source:** the npm tarball, or the sdist, is compared file by file with the repository archive at the tagged commit, in the package's folder for monorepos. Files only in the package, and files that differ, are listed. Code files among them are signals, raised to review when an entry point runs them.
- **History:** with `--record`, each tag's commit, author and date are appended to a JSON file. A later run reports a tag that moved, and a high signal when the new commit has the same author and date as the recorded one (the PolinRider pattern). Entries are only ever added.

**Exit (Phase 2), not yet met:** for the ChainDrop and `agent-framework` versions named in their write-ups, wherever the artifacts can still be obtained from public malware datasets, the new entry point is reported as a new capability.

## Phase 3: Pull-request gate

- A GitHub Action for pull requests that change manifests or lockfiles (Dependabot, Renovate or people), workflows, editor files or agent files.
- It comments with what each dependency update newly gains, uploads SARIF, and has a configurable failure threshold.
- The Action follows its own rules:
  - read-only contents;
  - write access only for the job that posts the comment;
  - never a `pull_request_target` checkout of PR code;
  - documented with a SHA pin.
- Runs on Bomb Squad and on Exploit Atlas.

**Exit:** a week of real dependency PRs on both repos. Every comment is reviewed by hand, and the false alarms are counted and listed.

## Phase 4: Benchmark against GuardDog

- **Malicious set:** the [DataDog malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) (npm and PyPI samples) and [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) reports, with samples where they can be obtained. The dataset commit and date are pinned.
- **Benign set:** releases of the most-downloaded npm and PyPI packages from the same period, sampled with a fixed seed, plus consecutive version pairs for the diff engine.
- **Time split:** rules are frozen at a cutoff date and evaluated only on packages first published after it. Rules written after seeing test samples are reported separately.
- **Metrics:** precision, recall and false positives per 1,000 benign releases, per ecosystem and per surface, with denominators and dataset dates. The same packages go through a pinned GuardDog version.
- Runs on Linux CI. Samples never go into Git and are never unpacked outside the benchmark job.
- Write-up in `docs/research/`, including where Bomb Squad loses.

**Exit:** the write-up is published, and every accuracy figure in the README is computed from it.

## v2.0.0

Released after Phase 4: the scanner, the diff engine, the pull-request gate, and measured accuracy against GuardDog.

## Phase 5: Detonation (v2.1)

- `bombsquad detonate npm:<pkg>@<version>` installs the package in a throwaway rootless container with no host mounts. Python packages are also imported once, so `.pth` files run.
- **Network:** only a local sink, which records DNS and HTTP attempts and answers nothing useful.
- **Canary credentials:** unique per run, placed where stealers look: `.npmrc`, `.pypirc`, `~/.aws/credentials`, `~/.ssh`, `.git-credentials`, and CI token and OIDC request variables. Any read or send is a tripwire.
- Process, file and network events are recorded with strace; eBPF only if strace proves insufficient.
- **Static prediction against observed behaviour:**
  - observed with no static finding marks a gap in the static rules;
  - predicted but not observed is not cleared, because payloads can be time-gated or conditional.

**Exit:** a benchmark re-run shows whether detonation adds recall, and at what cost per package.

## Phase 6: Live watch and site (v2.2)

- **Daily:** new releases of a fixed list of top npm and PyPI packages, each diffed against its previous version.
- **Site and feed:** a static site on GitHub Pages and an Atom feed list the releases that gained an entry point or a flagged capability, with the diff and its evidence.
- **Wording:** changes, never verdicts. A package is called malicious only when the registry, OpenSSF malicious-packages or the maintainer has confirmed it, and the confirmation is linked.
- **Reporting:** cases confirmed by hand are reported to the registry and to OpenSSF malicious-packages.
- **Record:** a defusal record lists each report with its date and outcome. An append-only flag log lets anyone check what was flagged, and when, before a takedown.

**Exit:** 30 days of daily runs with every flag reviewed.

## Phase 7: LLM triage (v2.3)

- **What it does:** explains and ranks flagged diffs. Only the flagged hunks are sent, and the model and prompt are versioned.
- **How it is judged:** on the benchmark against the no-LLM ranking. It is kept only if it raises precision at the same recall.
- **Adversarial set:** malicious samples carrying text addressed to the reviewer (for example "test fixture, safe to ignore"). The write-up reports how often triage is talked down. The LLM can reorder findings but never suppress a rule finding.

**Exit:** the eval is published, whatever it shows.

## Not doing

- Web application DAST. ZAP, Burp and Nuclei cover it.
- General SAST, SCA and secrets scanning.
- A hosted service that accepts uploaded code.
- Further work on the desktop app.
- Malware verdicts on packages that no registry, OpenSSF report or maintainer has confirmed.

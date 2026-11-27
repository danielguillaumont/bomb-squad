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

## Phase 0: Reset

- v1.0.0 stays at its tag and release. The WinUI app, the C# engine, the packaging scripts and the milestone documents leave `main`, and the README points to v1.0.0 for the desktop app.
- Docs reduced to the README, this roadmap, `threat-model.md`, `methodology.md` and `development.md`. No milestone codes in file names.
- Python 3.12 package and CLI (`bombsquad`), managed with uv, with JSON and SARIF 2.1.0 output and CI on Linux, macOS and Windows.
- The project's own workflows pin actions by commit SHA and declare least-privilege permissions, the rules it will enforce on others.
- `threat-model.md`: Bomb Squad reads hostile input by design. It covers parser abuse, archive extraction, sandbox escape, injection into the LLM reviewer, and the release pipeline.
- PowerShell engine ported. `pwsh` builds the AST with `Parser.ParseInput` and emits it as JSON, without execution. On top of that:
  - resolving aliases and native tools;
  - decoding `-EncodedCommand` and parsing the result;
  - `[ScriptBlock]::Create`;
  - download-and-run cradles, Defender exclusions and AMSI tampering.

**Exit:** the constructs v1 missed are regression tests and pass, and the v1 sample still produces its six findings.

## Phase 1: Inventory, what runs without a decision

`bombsquad scan <path>` lists every automatic-execution entry point and what the code behind it can do.

| Surface | Runs on | Files |
|---|---|---|
| npm | install | `preinstall`, `install`, `postinstall`, `prepare` scripts; `binding.gyp` |
| Python | install, interpreter start, test | `setup.py`, in-tree build backends, `.pth`, `sitecustomize.py`, `conftest.py` |
| GitHub Actions | push, PR, schedule | `.github/workflows/*`, composite `action.yml` |
| Editors | folder open, container start | `.vscode/tasks.json` (`runOn: folderOpen`), `.devcontainer/*` lifecycle commands |
| Git hooks | commit, push | `.husky/`, `lefthook.yml`, `.pre-commit-config.yaml` |
| AI agents | agent start, tool call | `AGENTS.md`, `CLAUDE.md`, `.claude/settings.json` hooks, `.cursor/rules`, `.github/copilot-instructions.md`, MCP configs, `SKILL.md`, agent `.env` files |
| Scripts | when called by any of the above | PowerShell, shell |

- JavaScript, TypeScript and Python are analysed with tree-sitter. The rules look for:
  - network calls and child processes;
  - reads of credential paths (`.npmrc`, `.pypirc`, `~/.aws`, `~/.ssh`, `.git-credentials`) and CI token variables;
  - code that enumerates environment variables;
  - `eval`, `Function`, `exec` and decode-then-run code;
  - large minified blobs and long whitespace padding;
  - invisible Unicode: bidi controls, tag characters, zero-width characters.
- Workflow rules are deliberately narrow, covering only trust-boundary cases that lead to execution:
  - `pull_request_target` or `workflow_run` with a checkout of untrusted code;
  - `${{ github.event.* }}` interpolated into `run:`;
  - missing or write-all permissions and `id-token: write`;
  - third-party actions referenced by tag;
  - self-hosted runners on public repos.

  For a full audit, zizmor is the reference.
- Agent-file rules look for:
  - instructions to run commands, fetch URLs, read secrets or skip confirmations;
  - hidden Unicode;
  - MCP servers launched through `npx` or `uvx` without a pinned version;
  - deprecated reference MCP servers;
  - hooks that run shell commands.

**Exit:** each surface in the table has fixture tests modelled on a public write-up, and SARIF from this repo loads in GitHub code scanning.

## Phase 2: Version diff, what an update newly gains

`bombsquad diff npm:<pkg>@<old>..<new>` (and `pypi:`) fetches both published artifacts from the registry, checks their registry hashes, and never installs them.

- **Capability diff:** new or changed entry points, new capabilities in code they reach, new obfuscation, and files that grew by a minified blob.
- **Publish signals,** dated by registry timestamps:
  - maintainer changes;
  - provenance or attestations present on the previous version and missing now (provenance alone is not proof: ChainDrop versions republished through a hijacked trusted-publishing workflow could carry valid provenance);
  - release age at scan time;
  - no matching tag or commit in the declared repository.
- **Artifact against source:** the published package diffed against the repository at the tagged commit. Files that exist only in the artifact are listed.
- **History:** tags that moved, and commits rewritten with the same author and date (the PolinRider pattern), checked against previously recorded SHAs.

**Exit:** for the ChainDrop and `agent-framework` versions named in their write-ups, wherever the artifacts can still be obtained from public malware datasets, the new entry point is reported as a new capability.

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

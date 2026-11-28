# Methodology

## Entry points

An entry point is code that runs without anyone choosing to run it. Each one in the report states its trigger, the command or code as written, and the files it reaches.

| Entry point | Trigger |
|---|---|
| `preinstall`, `install`, `postinstall` in `package.json` | `npm install`, including as a dependency |
| `preprepare`, `prepare`, `postprepare` | `npm install` in the repository, or as a git dependency |
| Scripts those hooks call with `npm run`, `pnpm`, `yarn` or `bun` | as the hook |
| `binding.gyp`, when there is no `install` or `preinstall` script | `npm install` runs `node-gyp rebuild`, which runs its `<!(…)` expansions |
| `.pth` lines that start with `import` | every Python start, once installed |
| `sitecustomize.py`, `usercustomize.py` | every Python start, once on the path |
| `setup.py`, in-tree build backends (`backend-path`) | building or installing from source |
| `conftest.py` | running pytest in or below its directory |
| Each job in `.github/workflows/*.yml` | the workflow's events |
| `action.yml`: composite steps, JavaScript `pre`/`main`/`post`, Docker image | any workflow step that uses the action |
| `.vscode/tasks.json` tasks with `runOptions.runOn: folderOpen`, and the tasks they `dependsOn` | opening the folder in a VS Code-based editor, once the workspace is trusted |
| `devcontainer.json` `initializeCommand` | on the host, whenever the dev container is created or started |
| `onCreateCommand`, `updateContentCommand`, `postCreateCommand`, `postStartCommand`, `postAttachCommand` | inside the dev container |
| `.husky/<hook>` | the git operation, once husky is installed (its `prepare` script does this on `npm install`) |
| `lefthook.yml` commands, scripts and jobs | the git operation, once `lefthook install` has run |
| `.pre-commit-config.yaml` local hooks and remote hook repositories | `git commit` and other installed stages, once `pre-commit install` has run |
| Agent instructions: `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md` and `.github/instructions`, prompts and agents, Cursor, Windsurf, Cline, Roo Code and Kiro rules, `.junie/guidelines.md`, Claude Code commands, subagents and rules, `SKILL.md` | every session of the agent that reads them, or when the command, subagent or skill is used |
| Claude Code hooks, `statusLine` and credential helpers in `.claude/settings.json`, and a plugin's `hooks/hooks.json`; Cursor `.cursor/hooks.json`; Gemini CLI hooks; Codex `notify` | the agent event they are attached to, once the folder is trusted |
| MCP servers in `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml`, `opencode.json`, `claude_desktop_config.json` and others | the agent's start, once the server is approved or the folder trusted |

### Reachability

- An npm hook's command, a workflow `run:` step, a task or lifecycle command and a git hook command are analysed as shell, or in the language of the step's `shell:` (bash, sh, pwsh, powershell, python). Workflow steps on a `windows` runner default to pwsh, and VS Code shell tasks under `windows` to PowerShell. `cmd` is not analysed and the report says so.
- A JavaScript, TypeScript, Python, shell or PowerShell file inside the package or repository becomes a target when a command runs it: as the command itself, as the script given to an interpreter (`node`, `python`, `bash`, `pwsh -File` and others), or through `uv run`, `poetry run` or `npx`. A file only passed as data, as in `cat x.sh` or `shellcheck x.sh`, is not a target. `${{ github.workspace }}`, `${{ github.action_path }}` and `${workspaceFolder}` are resolved for this.
- Lefthook scripts in `.lefthook/<hook>/`, pre-commit `script` hooks, a JavaScript action's `pre`, `main` and `post`, and husky hook files are targets directly. A JavaScript action's scripts may be anywhere in the scanned folder, because an action in a subfolder often runs `../lib/index.js` and the runner downloads the whole repository.
- Agent hook commands, MCP server commands and the shell code blocks in agent instructions follow the same rule. `$CLAUDE_PROJECT_DIR` and similar variables are resolved to the project, and a skill's commands are also resolved from the skill's folder. A `NODE_OPTIONS=--require` file in agent settings is a target too.
- Targets' relative `require` and `import` calls are followed, up to five levels and 500 files. Bare package names are not followed.
- Python targets' imports of modules inside the scanned folder are followed the same way, with each package's `__init__.py` on the way, so a `setup.py` that imports `mypkg.build` has `mypkg/__init__.py` and `mypkg/build.py` checked too. Absolute imports are looked up from the importing file's folder upwards; installed packages are not followed. `exec(f.read())` or `exec(compile(f.read(), …))` of a file opened by a path written in the code (string literals, `os.path.join`, `/`, and folders built from `__file__`) is followed the same way, whatever the file's extension, instead of being reported as BS-DE-006; when the file is not in the scan, BS-DE-006 stands. Functions the file defines itself named `exec`, `eval` or `compile` are not the built-ins.
- Code embedded with `node -e`/`-p`, `python -c`, `sh -c` or a `pwsh`/`powershell` command line is analysed in its own language, up to three levels deep. Its findings point at the line in the file that embeds it.
- A command line written out literally in a process call is analysed as shell: `os.system`, `os.popen`, `subprocess.*` (a string or a list of strings, with `sys.executable` read as `python`) and `asyncio` subprocesses in Python; `exec`, `execSync`, `spawn`, `execFile` and their sync forms, and `Bun.spawn`, in JavaScript. A command built at run time is reported only as a process start.
- JavaScript, Python and shell that no entry point reaches is not analysed unless it is named on the command line. PowerShell is analysed wherever it is.
- Findings in reached files have a `via` that starts with the entry point that reaches them.

### Correlation

BS-EX-001 is reported once per entry point when the code it reaches both collects secrets (BS-CR-001, BS-ENV-001 or BS-AG-003) and has network access (BS-NET-001, -002 or -003, or BS-AG-004). It sits at the entry point and names one finding of each kind. It does not prove that the collected values reach the network call; there is no data flow between files.

GitHub Actions entry points are left out of BS-EX-001. Workflows and actions use tokens and the network by design, and the official toolkit bundled into JavaScript actions reads the OIDC token variables, so the combination says little there. BS-GHA-006 takes its place for workflow steps.

## GitHub Actions

Workflows and `action.yml` are composed into YAML nodes with PyYAML's safe loader and never constructed into objects. `${{ }}` expressions are replaced with placeholders of the same length before a script is parsed, because GitHub substitutes them before the shell starts. Evidence shows the original expression. Findings in a `run: |` block point at the exact line and column.

The rules are deliberately narrow. For a full audit, zizmor is the reference.

- **BS-GHA-001 (high):** a workflow triggered by `pull_request_target`, `workflow_run` or `issue_comment` checks out the pull request's code. That means `actions/checkout` with a `ref` or `repository` taken from the pull request's head, `refs/pull/…` or the `workflow_run` head, or a `run:` step that does `gh pr checkout` or a `git fetch` or `checkout` of those refs.
- **BS-GHA-002:** a `${{ }}` expression in `run:` or in `actions/github-script`'s `script` that reads event text. It is high for the fields anyone outside the repository can set: issue, pull request and discussion titles and bodies, comment and review bodies, commit messages and author names and emails, wiki page names, the head branch and label, and the `workflow_run` head branch, title and commit. It is review for other `github.event` fields, except numbers, hashes, states, logins, URLs and `github.event.repository`. Workflow inputs are not reported. Values passed through `env:` and quoted in the script are the safe pattern and are not reported.
- **BS-GHA-003:** `permissions: write-all` (review), or jobs with no permissions block at either level (info, once per workflow). Workflows triggered only by `workflow_call` take the caller's permissions and are not reported as missing.
- **BS-GHA-004 (review):** `id-token: write`.
- **BS-GHA-005 (review):** `runs-on` with the `self-hosted` label. The scan cannot tell whether the repository is public.
- **BS-GHA-006:** a bash or sh step that uses a secret, through `${{ secrets.* }}`, `${{ github.token }}` or an `env:` variable set from one, and runs a network tool. It is high when the step uses `toJSON(secrets)`, collects the whole environment, or puts a secret in a request body (`-d`, `--data*`, `-F`, `--json`, `--post-data` and similar), in a URL query, or in data piped into the tool. It is review otherwise, for example for a token in an `Authorization` header or a webhook URL kept as a secret.
- **BS-PIN-001 (review):** a third-party action, reusable workflow or `docker://` image referenced by a tag or branch rather than a full commit SHA or `sha256` digest. Actions owned by `actions/` and `github/` are not reported. The same rule covers pre-commit `rev` values and lefthook `remotes`.

## Editors and git hooks

- `.vscode/tasks.json` and `devcontainer.json` allow comments and trailing commas. They are read by Bomb Squad's own JSONC reader, which keeps each key's position and stops at 200 levels of nesting.
- **BS-EP-002 (review):** a VS Code task with `runOn: folderOpen`. Its command and arguments, its `windows`, `linux` and `osx` variants, the tasks it `dependsOn`, and the `package.json` script of an `npm` task are analysed.
- **BS-EP-003 (review):** a dev container `initializeCommand`, which runs on the host. Every lifecycle command is analysed, in string, array and parallel-object form.
- Husky hook files, lefthook `run` commands, scripts and nested job groups, and pre-commit local hooks are analysed as shell. pre-commit `pygrep` and `fail` hooks are not commands and are skipped. Hooks that run in a container image are listed and not analysed.

## AI coding agents

### Instruction files

Markdown is split into front matter, fenced code blocks, inline code and HTML comments. Nothing is rendered, so every position is the file's own.

- Prose, front matter and HTML comments are matched line by line, one clause at a time, against fixed phrasings. A clause that negates the instruction is not reported: "never read `~/.ssh`" is a safety rule, and so is "never push without asking", which negates twice.
  - **BS-AG-001 (review):** skip confirmation or permission prompts ("without asking for confirmation", "don't ask for approval"), or flags such as `--dangerously-skip-permissions`, `--yolo` and `bypassPermissions`.
  - **BS-AG-002 (high):** ignore previous, system or safety instructions; do not tell or notify the user; act without the user noticing; hide something from the user.
  - **BS-AG-003 (review):** read, print, copy or send a credential file or token variable, from the same list as BS-CR-001.
  - **BS-AG-004 (review):** fetch, download, run, follow, send or post together with a URL, except `localhost` and other loopback hosts. A plain link is not reported.
- A match inside an HTML comment, which rendered Markdown does not show, is reported as high. So is a match in text hidden as Unicode tag characters, which are decoded for the check; BS-UC-001 reports the characters as well.
- Fenced code blocks are analysed in their language: no language or `sh`, `bash`, `console` and similar as shell, `powershell` and `pwsh` as PowerShell, `python`, `js` and `ts`. In terminal sessions, only lines after a `$ ` prompt are read. Inline code with a space in it is analysed as shell. Findings point at the exact line and column.
- In Claude Code commands and skills, `` !`command` `` runs when the command or skill is used. It is reported as BS-AG-005 and analysed as shell. An `allowed-tools` value that allows every shell command is BS-AG-006.
- `@path` imports in `CLAUDE.md` and `GEMINI.md` are followed up to five levels, inside the project only, and the imported files are checked as part of the same entry point.

### Configurations

- **BS-AG-005 (review):** every command hook, status line, credential helper (`apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`) and Codex `notify` command. Each is its own entry point, with its event as the trigger, and its command is analysed as shell.
- **BS-AG-006 (review):** `defaultMode: bypassPermissions`, an allow rule for every `Bash` command, `enableAllProjectMcpServers` and `enabledMcpjsonServers`, a Codex `approval_policy` of `never`, and in `.vscode/settings.json` `chat.tools.autoApprove`, `chat.tools.global.autoApprove` and `task.allowAutomaticTasks: on`.
- **BS-AG-007 (review):** in agent settings and `.env` files, `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` and similar endpoint variables, proxy variables, and variables that turn off TLS certificate checks. The evidence leaves out user names, passwords and query strings.
- **BS-AG-008 (high):** `NODE_OPTIONS` with `--require`, `--import` or a loader, `BASH_ENV`, `LD_PRELOAD`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES`, `PERL5OPT`, `RUBYOPT -r`, and Java agent options, in agent settings, MCP server environments and `.env` files.
- **BS-MCP-001 (review):** an MCP server started with `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `uvx`, `uv tool run` or `pipx run` without an exact version, or with `docker run` without an image digest. `cmd /c` is looked through. Local paths are not reported, and git sources count as pinned only with a full commit SHA.
- **BS-MCP-002 (review):** the npm and PyPI packages of the reference servers in [modelcontextprotocol/servers-archived](https://github.com/modelcontextprotocol/servers-archived): `@modelcontextprotocol/server-` `aws-kb-retrieval`, `brave-search`, `everart`, `gdrive`, `github`, `gitlab`, `google-maps`, `postgres`, `puppeteer`, `redis` and `slack`, and `mcp-server-sentry` and `mcp-server-sqlite`. `mcp-server-git` is still maintained in the main repository and is not reported.
- Remote MCP servers are listed as entry points with their URL, without the query string, and are not analysed.

## JavaScript, TypeScript, Python and shell

- JavaScript and TypeScript (including JSX and TSX) are parsed with tree-sitter, Python with the standard library's `ast`, and shell with tree-sitter-bash. Nothing is imported or evaluated.
- **Names:** `require` and `import` bindings are tracked within a file, so `const cp = require('child_process'); cp.exec(…)` and `from os import system` resolve.
- **Credentials:** strings that name a credential file (`.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `~/.aws`, `~/.ssh`, `~/.kube`, `~/.docker/config.json`, cloud metadata addresses and others) or a token variable (`GITHUB_TOKEN`, `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, CI OIDC variables and others). The full lists are in `src/bombsquad/code/common.py`.
- **Whole environment:** `process.env` or `os.environ` serialised, iterated, spread or formatted into text; `env`, `printenv`, `export -p`; `Get-ChildItem Env:` and `GetEnvironmentVariables()`. Also the whole environment held in an object, array or spread, or in a variable in the same file, that is then serialised or passed to a network call, such as `{ env: process.env }` in a `fetch` body or `json={"env": dict(os.environ)}` in `requests.post`. Passing the environment to a child process is not reported. The value is followed through literals and plain assignments in one file, not through functions or other files.
- **Decode then run:** `eval`, `Function`, `vm`, `exec` or `compile` with an argument that decodes (`atob`, `Buffer.from(…, 'base64')`, `base64`, `zlib`, `marshal`), and shell pipelines from a decoder into an interpreter.
- **Packed code:** an encoded blob of 2,000 characters or more, ten or more obfuscator-style `_0x` names, or a line over 5,000 characters.

### Text rules

These run on every text file in the scan, whatever its language:

- **BS-UC-001:** direction-changing controls, Unicode tag characters, runs of four or more variation selectors or private-use characters (HIGH), and zero-width characters (REVIEW). A byte order mark at the start of a file, single emoji variation selectors, subdivision flag emoji (a black flag, two to seven tag letters or digits, then the cancel tag) and zero-width non-joiners next to letters of scripts that need them (Persian, Indic and others) are ignored.
- **BS-OB-001:** code after 100 or more spaces or tabs on a line. Leading indentation is ignored when it is under 200 characters, or within 100 characters of the line above, as in deeply nested data. The rest of the line must be able to run: two words, or a word and an operator such as `(`, `=`, `;` or `|`. A lone word or punctuation is not reported, such as a docstring wrapped after a run of spaces or a caret line under an error message. Markdown and plain-text files are skipped, because rendering collapses whitespace, except agent instruction files, which agents read raw.

## PowerShell

### Parsing

- `src/bombsquad/powershell/dump_ast.ps1` runs in PowerShell 7 (`pwsh`), or in Windows PowerShell 5.1 when pwsh is not installed.
- It calls `Parser.ParseInput` and writes out every command, member call, string literal, type name, variable assignment, function definition and parse error, each with its UTF-16 offsets, lines and columns.
- The parser version is in every report. Windows PowerShell 5.1 rejects PowerShell 7 syntax such as `&&` and ternaries, and the report says so when it matters.
- Before parsing, `using module` and `using assembly` statements are replaced with spaces (see the [threat model](threat-model.md)).

### Resolving names

- **Command names** are resolved through built-in aliases, module-qualified names, paths and `.exe` suffixes, and a list of native tools.
- **Version-dependent names** are reported with both meanings:
  - `curl` and `wget` download in both, either as aliases or as programs;
  - `sc` is `Set-Content` in 5.1 and `sc.exe` in PowerShell 7.
- **Literal folding:** a name or argument built only from string literals is rebuilt by the dumper's own code, never by PowerShell. It handles `+`, `-join`, `-f`, `[char]` and `[char[]]` conversions, and parentheses. The finding records the original expression.
- **Parameters** match the unambiguous prefixes PowerShell accepts, for example `-Exclu` for `-ExclusionPath`, and the en and em dashes PowerShell accepts in place of `-`.

### Decoded content

These are parsed and analysed as PowerShell, up to three levels deep:

- `-EncodedCommand` (any accepted prefix), including through `Start-Process`;
- `-Command` text, and the first plain argument to `powershell.exe`, which it treats as a command;
- base64 literals passed to `FromBase64String`;
- literal text passed to `Invoke-Expression`, `InvokeScript` and `[ScriptBlock]::Create`.

Findings inside decoded content point at the outer command in the file, and their `via` says how they were reached.

### Data flow

A download counts as run (BS-NET-002) in three cases:

- it sits inside the arguments of the call that evaluates code;
- it is earlier in the same pipeline;
- it is assigned to a variable that the evaluating call later reads.

There is no other data flow: values that pass through functions, loops or other scripts are not followed.

### Rules

`bombsquad rules` lists all 47 rules, 17 of them for PowerShell. Each finding includes:

- the rule's effect;
- its limits;
- a next step;
- any limit specific to that finding, such as a function in the same script that shadows the cmdlet.

Rules still run on files with parse errors, and the errors are reported. PowerShell would refuse to run such a file as written, but skipping it would let one deliberate error hide everything else.

### What the analysis cannot see

- Values computed at run time: variables from outside the script, downloaded content, and environment-dependent paths.
- Code in modules, assemblies or other scripts the script loads.
- Whether the code is reachable, for example `if ($false) { … }`. A finding means the code is present, not that it runs.
- Behaviour of native tools beyond the arguments listed in each rule.
- Code in installed dependencies, and dynamic imports (`importlib`, `__import__`, `require` of a computed path).
- Whether collected values reach a network call: BS-EX-001 is co-occurrence, not data flow.
- In workflows: values that reach a script through `env:`, step outputs or files; the repository's default token permissions and whether it is public; and the code of reusable workflows, actions and container images fetched from elsewhere. BS-GHA-006 looks only at the step's own bash or sh script.
- Remote pre-commit hooks, lefthook remotes and `extends`, husky v4 and `simple-git-hooks` configuration in `package.json`, and editor settings outside the repository.
- A file that GitHub, VS Code or a hook tool accepts but these readers reject is reported as not read, and nothing in it is analysed.
- In agent instructions: anything phrased differently from the fixed phrasings, split across lines, written in another language, or only implied. Quoted examples of bad instructions are reported like real ones. Whether an agent would follow an instruction is not known.
- Agent settings outside the repository (user and enterprise settings), which can add hooks or override approvals, and the code of MCP servers fetched from registries or images.
- Embedded PowerShell when no PowerShell is installed: it is noted as not analysed. A PowerShell file named on the command line still needs PowerShell.

## Version diff

`bombsquad diff npm:<name>@<old>..<new>`, `pypi:<name>@<old>..<new>`, or two local folders or archives.

- **Fetching:** the npm package document or the PyPI JSON API gives each version's artifacts and hashes. Requests go only to `registry.npmjs.org`, `pypi.org` and `files.pythonhosted.org` over HTTPS, redirects included, with size limits. An artifact whose SHA-512 (npm, from `dist.integrity`) or SHA-256 (PyPI) differs from the registry's is not opened. When npm gives only a SHA-1 `shasum`, that is used and noted.
- **Which artifacts:** the npm tarball; for PyPI, the sdist and one wheel: a pure-Python `none-any` wheel, otherwise one for Linux on x86-64 (CPython 3.12 or the stable ABI first). Platform-specific wheels other than the one chosen are not compared. Each artifact is unpacked into a folder named for its kind (`npm-tarball`, `sdist`, `wheel`). When the two versions ship different kinds, both are scanned from above those folders, so an added sdist does not make the unchanged wheel look new.
- **Unpacking:** regular files only, written under a temporary folder that is deleted afterwards. Links, devices, paths that climb out with `..`, and names that differ only in case are skipped and listed in the report's notes. Leading slashes and drive letters are dropped, as npm's and Python's unpackers drop them, and names Windows reserves or cannot hold are renamed (`a:b.js` to `a_b.js`), so a file is renamed in the notes rather than hidden from the scan. More than 20,000 members or 500 MB decompressed stops the diff.
- **Published packages:** a registry release or a package archive is scanned as a package. Workflows, git hooks, editor and agent settings, `conftest.py`, npm `prepare` scripts (npm runs them for a local or git install, not for a package from the registry), and a `setup.py` below a folder that is itself a Python project or wheel root (such as a module named `setup.py`) inside it are still listed, but their findings are reported at info with a note, because installing the package does not run them. So are findings in PowerShell files that no entry point runs. Hidden characters and whitespace padding keep their level wherever they are, because they mislead a reviewer whether or not the file runs. `bombsquad scan --package` does the same for a folder.
- **Matching:** entry points match by surface, kind and file, and are reported as changed when their command changes. Findings match by rule, file and evidence, ignoring line numbers and whitespace, so code that only moved is not reported again. A finding that appears twice in the new version and once in the old one is reported once as new.
- **Minified lines:** a JavaScript, TypeScript, Python, shell or PowerShell file that has a line of 1,000 characters or more in the new version and none in the old one, or is new and has one.
- **Publish signals:**
  - `publisher-changed` and `maintainers-changed` (review): npm's `_npmUser` and `maintainers` for each version. Only names are kept; email addresses are not. PyPI does not publish who uploaded a release.
  - `provenance-missing` (review): npm `dist.attestations`, or a PyPI attestation bundle from the integrity API, on every artifact of the old version and on none of the new one. Provenance shows where a package was built, not that its code is benign.
  - `repository-changed` (review): the declared repository URL differs.
  - `recent-release` (review) within seven days of the scan, otherwise `release-age` (info). These are registry publish times.
- `--fail-on` applies to new findings and signals only.

### Against the source

`--source` compares the new version with its declared repository, when that is on GitHub. Requests go only to `api.github.com` and `codeload.github.com`, without credentials, so GitHub's unauthenticated rate limit applies; a failed request leaves a note and an incomplete comparison.

- **Tag:** the first of `v<version>`, `<version>`, `<name>@<version>`, and the unscoped name with `@`, `-v` or `-`, that exists. Annotated tags are followed to their commit.
  - `no-matching-tag` (info): none exists. Many projects do not tag releases. For npm, the comparison then uses `gitHead`, the commit npm recorded at publish time, when there is one.
  - `tag-not-at-published-commit` (review): npm's `gitHead` differs from the tag's commit.
- **Files:** the npm tarball, or the sdist, is compared with the repository archive at that commit, inside the folder npm's `repository.directory` names. Content is compared after normalising line endings. `package.json`, which npm rewrites, and `PKG-INFO`, `*.egg-info` and `setup.cfg`, which sdist builds generate, are not compared. Wheels are not compared, because they are laid out for installation.
  - `only-in-artifact`: code files in the package that the repository does not have.
  - `differs-from-source`: files in both whose content differs.
  - Both are review when an entry point runs one of the files, and info otherwise. Build output such as bundles and compiled files is often published without being committed, so a difference is a lead, not a finding.
- **History:** `--record FILE` implies `--source`. Each tag's commit, with its author, author date and subject from the API, is appended to the file with the time it was seen. Nothing is removed or rewritten; an unreadable file is left alone and noted.
  - `tag-moved` (review): the tag now points at a different commit from one recorded earlier.
  - `commit-rewritten` (high): the new commit has the same author name and author date as the recorded one, which is what rewriting history and force-pushing the tag looks like.
  - A tag that moved before the first recorded run is not seen.
- GitHub generates archives on request and publishes no hash for them, so unlike registry artifacts they are not checked against one.

## Pull-request gate

`bombsquad gate BASE HEAD`, where both are checked-out folders. The `action.yml` Action checks out the pull request's base commit in a git worktree, outside the workspace, and passes both folders.

- **Repository:** both folders are scanned and compared as in [Version diff](#version-diff). New and changed entry points, new findings and new minified lines are reported, wherever they are: workflows, actions, editor and hook files, agent files, package scripts and code.
- **Dependencies:** pinned versions are read from `package-lock.json` and `npm-shrinkwrap.json` (lockfile versions 1 to 3), `uv.lock`, `poetry.lock`, and `name==version` lines in `requirements*.txt`.
  - Only npm registry and PyPI packages are read. Git, path, link and private-index entries are counted in the notes.
  - `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `Pipfile.lock` and `pdm.lock` are noted as not read.
  - Each version the head pins and the base did not is paired with the base version it most likely replaces: one that was removed, else the closest lower one. It is then reviewed as `bombsquad diff` would.
  - A package new to the lockfile is reviewed against nothing, so everything it has is new.
- **Actions:** every remote `uses:` in `.github/workflows/*.yml` and in any `action.yml`, for steps and for reusable workflows. Local actions, `docker://` images and references built from expressions are skipped.
  - A reference the head uses and the base did not is paired with the reference to the same action that it replaces.
  - The action's repository is fetched from `codeload.github.com` at both references and compared. Only the action that is used, or the reusable workflow, is reported, with the files its entry point reaches anywhere in its repository. The action repository's own workflows and tooling never run in the repository that uses it.
  - `action-updated` (info) links GitHub's comparison of the two commits; `action-added` (info) marks an action that was not used before.
  - Actions that an updated action itself uses are not followed. Docker actions' images are not compared.
  - Actions are reviewed with direct dependencies, ahead of transitive ones, within the same `--max-packages` limit.
  - Direct dependencies come first, up to `--max-packages` (25 by default). The rest are listed as not reviewed. A version the registry cannot serve is listed with the error.
- **Comment:** text from the pull request or a registry is escaped. Paths, commands and evidence go in code spans that a backtick cannot end early, other text has Markdown and HTML escaped, and `@` is written as an entity so no one is notified. The comment is cut to fit GitHub's limit, and the JSON report keeps everything.
- **SARIF** holds the repository's new findings. Dependency findings are in files the repository does not have, so they stay in the comment and the JSON.
- `--fail-on` applies to new findings and signals, in the repository and in dependencies.

## Detonation

`bombsquad detonate npm:<name>@<version>` or `pypi:<name>@<version>` installs one release in a throwaway container and records what it does. `--artifact FILE` detonates a local archive. It runs only on Linux with Docker, and is meant for disposable CI runners. The [threat model](threat-model.md) lists its controls.

- **Sandbox:**
  - Two containers share an internal Docker network with no route out: the package's container, and the sink.
  - Nothing on the host is mounted in the package's container. It has no capabilities except the three strace needs, to trace and to switch users. The package runs as an unprivileged user with none, and `no-new-privileges`.
  - Images are built from base images pinned by digest.
- **npm:** the tarball is unpacked into `node_modules` and `npm rebuild` runs its `preinstall`, `install` and `postinstall` scripts, and node-gyp for `binding.gyp`. Its dependencies are beside it in `node_modules`, without their own install scripts run.
- **PyPI:**
  - The sdist is detonated when there is one, otherwise a wheel.
  - pip installs it with no index, using build backends preinstalled in the image, so `setup.py` or the build backend runs. Its dependencies come from the wheels fetched before the sandbox started; if they do not satisfy it, it is installed without dependencies.
  - When the sdist does not build there (often because its build dependencies are missing), the release's wheel is installed instead, as `--wheel FILE` does for a local sdist. What the failed build ran is still in the trace, and the report says which was installed.
  - Each top-level module is then imported once, which also runs any `.pth` file it installed.
- **Dependencies:** fetched before the sandbox starts, by a separate container of the same image. That container has Docker's default network but neither the package nor the fake credentials, and it runs no package code: npm uses `npm install --ignore-scripts`, and PyPI uses `pip download --only-binary=:all:`. `--no-dependencies` skips this step.
  - What it fetches is what the release declares from the registry: npm `dependencies` and `optionalDependencies`, without git, URL, file or alias specifiers. For PyPI, the first source that lists any: wheel `METADATA` or sdist `PKG-INFO`, egg-info `requires.txt`, `pyproject.toml`, or a literal `install_requires` in `setup.py`. Direct URL references are left out.
  - Only regular files with plain relative names come back, up to 300 MB, 100,000 files and 180 seconds.
- **Fake credentials:**
  - Files: `.npmrc`, `.pypirc`, `~/.aws/credentials`, `~/.ssh/id_ed25519` and `.git-credentials`.
  - Variables: npm, GitHub, AWS and PyPI tokens, and the GitHub Actions OIDC request variables.
  - They are unique to each run.
- **What is recorded:**
  - strace, running as root, records processes, files opened and connection attempts. The package runs as an unprivileged user.
  - The sink answers every DNS A query with its own address. It records names, TCP connections on common ports, HTTP request lines, TLS server names and the first 64 KB of each connection.
  - TLS is read too. The sink makes a certificate authority for each run and issues a certificate for each server name a client asks for. The package's container trusts that authority through its system bundle and `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE`. The authority's key never leaves the sink.
  - A fake credential that appears in what the sink received counts as sent: as is, hex, URL-encoded, base64 at any alignment, or in a DNS name.
- **Package code:** what npm's `sh -c` for a lifecycle script, pip's build-backend helper or its `setup.py` caller, and the import step start, and everything below them. A thread, or a fork that has not called exec, counts as the process it came from.
  - npm reading `~/.npmrc` itself is expected and not reported.
  - Compilers, linkers, `make` and `git` are listed as build tools, not as programs started.
- **Against the static scan:** the rule IDs of the static findings that installing runs are mapped to what they predict: network, credentials read, credentials sent, programs started and persistence.
  - Observed and predicted is confirmed.
  - Observed with no static finding marks a gap in the static rules.
  - Predicted but not observed is not cleared.
- **What it cannot see:**
  - Code that needs a dependency that could not be fetched fails. For PyPI that includes a dependency with no wheel, and one declared only in code that builds the list at run time.
  - Dependencies' own install scripts do not run, so a payload placed in a dependency's install script is not seen.
  - A client that pins a certificate or brings its own list of authorities fails the TLS handshake, and then only its server name is seen.
  - Reading environment variables leaves no trace.
  - One timed run as a fresh user does not trigger payloads gated on time, host or a later run.
  - Nothing observed does not mean safe.

`tests/test_detonate_container.py` runs harmless stand-in packages in real containers on Linux CI. Real packages are not detonated there.

## Daily watch

`python -m watch run --since … --until …` checks the top packages (500 per ecosystem by default) of the benchmark's pinned popular lists for releases first published in the window.

- **Which releases:** stable versions only, since an install without an exact version does not pick a pre-release. Each is compared, with `bombsquad diff`, against the highest lower stable version published before it, so a backport to an old major is compared within that major.
- **Queued for review:** a new or changed entry point that installing runs, a new finding at review or high, or a publish signal at review. Release age is left out, because every release in the window is recent.
- **What is kept:** versions, publish times, entry point counts and surfaces, rule IDs and signal names. Evidence is not kept.
- **Wording:** queued is not a verdict, and nothing is published or reported before a human has reviewed it. Not queued does not mean safe: the diff cannot see code fetched at run time, or payloads gated on time or conditions.

### Review, flag log and site

- **Review:** `python -m watch review npm:<name>@<version> --queue … --diff … --outcome listed|"not listed" --note … --reviewer … --log flags.jsonl` records a person's decision about a release the run queued, and nothing else can add to the flag log. A listed release keeps, from the `bombsquad diff --format json` the reviewer read, the entry points it gained or changed, its new findings at review or high, and its publish signals at review or high, each command and piece of evidence cut to 300 characters. A later review of the same release takes its place, so a release can be taken off the list; the earlier entry stays.
- **Defusal record:** `python -m watch report` records a report sent to npm, PyPI or OpenSSF malicious-packages, only about a release a review listed. `python -m watch outcome` records what became of it in a later entry. `confirmed` means the registry, OpenSSF or the maintainer confirmed the release malicious, and it needs the https link that shows it, as `removed` does.
- **Append-only:** both files are hash-chained JSON Lines. Each entry holds its sequence number, when it was recorded, the hash of the entry before it and its own SHA-256. `python -m watch verify FILE --head SEQ:HASH` checks the chain and that an entry someone kept is unchanged. The chain makes a rewrite detectable to anyone holding an earlier head, not impossible; the site shows the current heads so they can be kept.
- **Site and feed:** `python -m watch site` builds static pages and an Atom feed from the two files only, after checking both chains. A release is called malicious only beside a `confirmed` outcome and its link. Every value from a registry or a package is escaped, links are built only from names and versions that pass the registry's rules or from https links a person recorded, and the pages carry no script under a content security policy that allows none.

## Accuracy

Detection rates come only from the benchmark below. Every figure states its counts, the dataset commit and date, and GuardDog's result on the same packages. The current figures are in the [write-up](research/guarddog-benchmark.md): a development sample, which is in-sample, and a [held-out sample](research/guarddog-benchmark.md#held-out-sample). Both are retrospective, because the time-split set is empty for the pinned dataset commit.

### How the benchmark works

`.github/workflows/benchmark.yml` runs `python -m benchmark` on a GitHub-hosted Linux runner, started by hand. Nothing in it runs on a development machine.

- **Malicious set:** the DataDog malicious-software-packages-dataset at a pinned commit.
  - The repository is fetched without file contents. Samples are chosen from its file listing, and only the chosen ones are downloaded.
  - One version is chosen per package name, so a campaign of near-identical versions counts once, and then a seeded sample per ecosystem.
  - Samples are decrypted and unpacked with the same rules as registry packages, and any package archive inside is unpacked too. Both tools get the same folder: the shallowest one with a `package.json` (npm), or with `setup.py`, `pyproject.toml`, `setup.cfg` or `PKG-INFO` (PyPI).
  - The date in a sample's name is when DataDog found it, not when it was published.
- **OpenSSF reports:** each malicious sample is looked up in [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) at a pinned commit (`benchmark/openssf.py`), a confirmation independent of DataDog's label.
  - Only report files are fetched: the repository is listed without file contents, and only the sampled names' report folders are checked out.
  - A report confirms the sample when it lists the version, when its range starts at that version with no end, or when it affects every version. Other ranges are not evaluated, so such a sample counts as named, not confirmed. Withdrawn reports are left out.
  - The scores add recall on the confirmed samples, for both tools, with how many samples each kind of report covers. A report confirms that a version was malicious, not when the compromise began.
- **Benign set:** a seeded sample from the 1,000 most-downloaded packages per ecosystem.
  - The lists come from `npm-high-impact` 1.13.0 (npm) and hugovk/top-pypi-packages at commit `29c0d4c38c28` of 2026-11-01 (PyPI).
  - For each package, the highest stable version published on or before the dataset commit's date is downloaded and checked as `bombsquad diff` does. For PyPI, that is the sdist and one wheel. A package that has only published pre-releases gets its highest pre-release.
  - Releases over the 100 MB download limit, such as GPU wheels, cannot be checked and are left out.
  - A popular release is assumed benign; a compromised one in the sample would count as a false positive.
  - **Updates**, when the workflow's `version-pairs` input is on (`run --version-pairs`): each benign release is also diffed, with `bombsquad diff`, against the highest lower version published before it (stable if it is stable), as the pull-request gate reviews an update. Every alarm here is a false alarm on an ordinary update, counted at four thresholds: a new review or high finding, a new high finding, a new or changed entry point that installing runs (so not a workflow or git hook shipped in an sdist), and a new finding or a publish signal at review. `recent-release` is left out, because it is measured from when the benchmark runs. The scores list the rules behind new findings. There are no malicious pairs, because most dataset samples have no earlier release; the named incidents below are the malicious updates.
- **Time split:** the cutoff is the commit date of the Bomb Squad commit being run. Packages DataDog found after it are the `after-cutoff` set, which the rules could not have been written for; the rest are `retrospective`. Many rules follow public write-ups of campaigns in the retrospective set, and rules were changed after seeing the rule counts of an earlier run on it, so only `after-cutoff` figures measure detection of the unknown.
- **Held-out sample:** the workflow's `seed` and `leave-out` inputs (`--seed` and `--exclude-selection SEED:COUNT`) choose a fresh sample that leaves out every package earlier runs chose. The left-out packages are worked out again from the run's own listing. For seed 2026 at the pinned commit, that reproduces the 400 malicious and 400 benign packages of the development runs exactly.
  - It is held out by package, not by campaign: near-identical packages of one campaign can fall on both sides.
  - It is less in-sample than the retrospective set, not a replacement for the time split.
  - The protocol is fixed before it runs: one run on `main` at seed 2027, leaving out `2026:200,2026:5`, its figures published whatever they are, and no rule changed after seeing them reported as held-out again.
- **Detectors:**
  - Bomb Squad runs `scan --package`, as `bombsquad diff` scans a release, and flags a package with a high finding, or, as a second detector, with a review or high finding. Output without a result, such as a crash, counts as an error.
  - GuardDog 3.2.0, with its dependencies as of 2026-11-20, at three thresholds: its risk label `high_risk`, its label `suspicious` or `high_risk`, and any matched rule (the criterion of its exit code). GuardDog 3 labels a package from a 0–10 risk score that pairs capabilities with threat indicators.
  - GuardDog is given the folder, so its registry-metadata rules do not run. Bomb Squad's `scan` reads no registry metadata either.
  - Each tool runs in its own process with a 300-second limit. A timeout or crash counts as an error for that tool and is reported, not counted as a miss or a pass.
  - **Detonation**, only when the workflow's `detonate` input is `benign` or `all` (`run --detonate`), is scored on the packages it ran on.
    - Inputs: benign releases are fetched again as the registry serves them, with the sdist preferred. A PyPI sample installs the archive it holds, or its folder packed as an sdist. An npm sample installs from its folder.
    - Limits: 60 seconds each, two at a time.
    - Where: with `benign`, on a GitHub-hosted runner. With `all`, the whole job runs on a disposable self-hosted VM ([setup](development.md#detonation-vm)), and it refuses to start on any other runner.
    - It flags a package when package code read or sent a fake credential, or wrote somewhere that persists. A second detector counts anything observed. A third flags what either Bomb Squad at review or high, or detonation, flags.
    - Its gaps are compared with all of Bomb Squad's rule IDs for that package, including findings at info that installing does not run, so they are never overstated.
    - Scores give the median and total seconds per package, and how many runs failed, timed out, or ended with the install or import step exiting non-zero. In that last case, what ran before the failure was traced, but not the rest. They also count PyPI releases whose wheel was installed because the sdist did not build.
- **Scores:** recall on malicious packages, false positives per 1,000 benign releases, and precision on this mix, per ecosystem and split. Recall is also broken down by the kind of entry point Bomb Squad found, with the same counts for GuardDog. Every rate is given with its numerator and denominator.
  - Precision depends on the ratio of malicious to benign packages here, which is not the ratio in the wild.
  - Most of the dataset was found by GuardDog, which favours it.
- **Named incidents:** `python -m benchmark incidents` takes each version an OpenSSF malicious-packages report confirms for ChainDrop and `agent-framework`. Where the dataset commit has its sample, it compares the sample with the highest stable release published before it, from the registry, as `bombsquad diff` compares an update, in package mode. Only artifacts of the same kind are compared (npm tarball, sdist, wheel). It reports new and changed entry points and new findings at high and review. A version the dataset does not have is reported as missing, not as a miss.
- **What is kept:** the uploaded results hold package names, versions, rule IDs, levels and timings, detonation categories and counts (not DNS names, commands or sent bytes), for updates the counts of new entry points, the rule IDs of new findings and the names of publish signals, and for named incidents the kinds and paths of entry points. Evidence and sample content are not kept.

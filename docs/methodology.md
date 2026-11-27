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

### Reachability

- An npm hook's command, a workflow `run:` step, a task or lifecycle command and a git hook command are analysed as shell, or in the language of the step's `shell:` (bash, sh, pwsh, powershell, python). Workflow steps on a `windows` runner default to pwsh, and VS Code shell tasks under `windows` to PowerShell. `cmd` is not analysed and the report says so.
- A JavaScript, TypeScript, Python, shell or PowerShell file inside the package or repository becomes a target when a command runs it: as the command itself, as the script given to an interpreter (`node`, `python`, `bash`, `pwsh -File` and others), or through `uv run`, `poetry run` or `npx`. A file only passed as data, as in `cat x.sh` or `shellcheck x.sh`, is not a target. `${{ github.workspace }}`, `${{ github.action_path }}` and `${workspaceFolder}` are resolved for this.
- Lefthook scripts in `.lefthook/<hook>/`, pre-commit `script` hooks, a JavaScript action's `pre`, `main` and `post`, and husky hook files are targets directly.
- Targets' relative `require` and `import` calls are followed, up to five levels and 500 files. Bare package names are not followed.
- Code embedded with `node -e`/`-p`, `python -c`, `sh -c` or a `pwsh`/`powershell` command line is analysed in its own language, up to three levels deep. Its findings point at the line in the file that embeds it.
- JavaScript, Python and shell that no entry point reaches is not analysed unless it is named on the command line. PowerShell is analysed wherever it is.
- Findings in reached files have a `via` that starts with the entry point that reaches them.

### Correlation

BS-EX-001 is reported once per entry point when the code it reaches both collects secrets (BS-CR-001 or BS-ENV-001) and has network access (BS-NET-001, -002 or -003). It sits at the entry point and names one finding of each kind. It does not prove that the collected values reach the network call; there is no data flow between files.

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

## JavaScript, TypeScript, Python and shell

- JavaScript and TypeScript (including JSX and TSX) are parsed with tree-sitter, Python with the standard library's `ast`, and shell with tree-sitter-bash. Nothing is imported or evaluated.
- **Names:** `require` and `import` bindings are tracked within a file, so `const cp = require('child_process'); cp.exec(…)` and `from os import system` resolve.
- **Credentials:** strings that name a credential file (`.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, `~/.aws`, `~/.ssh`, `~/.kube`, `~/.docker/config.json`, cloud metadata addresses and others) or a token variable (`GITHUB_TOKEN`, `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, CI OIDC variables and others). The full lists are in `src/bombsquad/code/common.py`.
- **Whole environment:** `process.env` or `os.environ` serialised, iterated, spread or formatted into text; `env`, `printenv`, `export -p`; `Get-ChildItem Env:` and `GetEnvironmentVariables()`. Passing the environment to a child process is not reported.
- **Decode then run:** `eval`, `Function`, `vm`, `exec` or `compile` with an argument that decodes (`atob`, `Buffer.from(…, 'base64')`, `base64`, `zlib`, `marshal`), and shell pipelines from a decoder into an interpreter.
- **Packed code:** an encoded blob of 2,000 characters or more, ten or more obfuscator-style `_0x` names, or a line over 5,000 characters.

### Text rules

These run on every text file in the scan, whatever its language:

- **BS-UC-001:** direction-changing controls, Unicode tag characters, runs of four or more variation selectors or private-use characters (HIGH), and zero-width characters (REVIEW). A byte order mark at the start of a file and single emoji variation selectors are ignored.
- **BS-OB-001:** code after 100 or more spaces or tabs on a line. Leading indentation under 200 characters is ignored.

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

`bombsquad rules` lists all 37 rules, 17 of them for PowerShell. Each finding includes:

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
- Code in installed dependencies, and Python imports: only JavaScript relative imports are followed.
- Whether collected values reach a network call: BS-EX-001 is co-occurrence, not data flow.
- In workflows: values that reach a script through `env:`, step outputs or files; the repository's default token permissions and whether it is public; and the code of reusable workflows, actions and container images fetched from elsewhere. BS-GHA-006 looks only at the step's own bash or sh script.
- Remote pre-commit hooks, lefthook remotes and `extends`, husky v4 and `simple-git-hooks` configuration in `package.json`, and editor settings outside the repository.
- A file that GitHub, VS Code or a hook tool accepts but these readers reject is reported as not read, and nothing in it is analysed.

## Accuracy

Not measured yet. Detection rates will come only from the benchmark in [Phase 4](roadmap.md#phase-4-benchmark-against-guarddog): time-split, compared with GuardDog on the same packages, with denominators and dataset dates.

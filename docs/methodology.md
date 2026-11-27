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

### Reachability

- An npm hook's command is analysed as shell. Each word that names a JavaScript, TypeScript, Python, shell or PowerShell file inside the package directory makes that file a target.
- Targets' relative `require` and `import` calls are followed, up to five levels and 500 files. Bare package names are not followed.
- Code embedded with `node -e`/`-p`, `python -c`, `sh -c` or a `pwsh`/`powershell` command line is analysed in its own language, up to three levels deep. Its findings point at the line in the file that embeds it.
- JavaScript, Python and shell that no entry point reaches is not analysed unless it is named on the command line. PowerShell is analysed wherever it is.
- Findings in reached files have a `via` that starts with the entry point that reaches them.

### Correlation

BS-EX-001 is reported once per entry point when the code it reaches both collects secrets (BS-CR-001 or BS-ENV-001) and has network access (BS-NET-001, -002 or -003). It sits at the entry point and names one finding of each kind. It does not prove that the collected values reach the network call; there is no data flow between files.

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

`bombsquad rules` lists all 28 rules, 17 of them for PowerShell. Each finding includes:

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

## Accuracy

Not measured yet. Detection rates will come only from the benchmark in [Phase 4](roadmap.md#phase-4-benchmark-against-guarddog): time-split, compared with GuardDog on the same packages, with denominators and dataset dates.

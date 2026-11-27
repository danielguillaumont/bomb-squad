# Methodology

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

`bombsquad rules` lists the 17 rules. Each finding includes:

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

## Accuracy

Not measured yet. Detection rates will come only from the benchmark in [Phase 4](roadmap.md#phase-4-benchmark-against-guarddog): time-split, compared with GuardDog on the same packages, with denominators and dataset dates.

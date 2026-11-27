# BOMB SQUAD

**Find what runs before anyone chooses to run it.**

Bomb Squad reviews third-party code before it runs. Version 2 is being built step by step ([roadmap](docs/roadmap.md)). It will cover dependencies, workflows, editor and agent configs, and scripts. Today it covers PowerShell, the language of most paste-and-run attacks.

It reads a script with PowerShell's own parser. It then reports what the script could do to the machine, with the exact source, how it was found, and what the analysis could not see. **It never runs the script.**

```text
$ bombsquad scan samples/example.ps1
samples/example.ps1
  6:5  review  BS-FS-001  Deletes files or directories
      Remove-Item -LiteralPath 'demo-cache'
  7:5  high    BS-SS-001  Changes Microsoft Defender settings
      Set-MpPreference -DisableRealtimeMonitoring $true
  ...
```

## What it finds

17 rules, listed by `bombsquad rules`, cover:

- **Destructive and persistent changes:**
  - file deletion;
  - registry writes, and separately writes to autostart keys;
  - local accounts and groups;
  - scheduled tasks and services.
- **Security tooling:** Defender settings and exclusions, and tampering with AMSI or script logging.
- **Downloads:** content fetched from the network, and downloaded content that is then run. That covers the download inside the call, the download piped into it, and the download stored in a variable first.
- **Dynamic code:**
  - `Invoke-Expression` and script blocks built from text;
  - commands whose name is chosen at run time;
  - compiled C# and loaded assemblies;
  - modules loaded from a path.
- **Encoded and obfuscated code:**
  - `-EncodedCommand` is decoded and analysed, including through `Start-Process`. So are `-Command` text, base64 literals and literal text passed to `Invoke-Expression`.
  - Names assembled from string literals, such as `('Remove-' + 'Item')` or `-join [char[]](…)`, are folded back to the command they name.
- **The same action under other names:**
  - aliases (`rm`, `del`, `iwr`) and module-qualified names;
  - native tools (`reg`, `schtasks`, `sc.exe`, `net`, `certutil`, `bitsadmin`);
  - en and em dashes, which PowerShell accepts in place of `-`.

Every finding carries its source location, the evidence, how it was resolved and what the analysis could not see. Accuracy has not been measured yet. The benchmark against GuardDog is [Phase 4](docs/roadmap.md#phase-4-benchmark-against-guarddog), and until it runs this README states no detection rates. **No findings does not mean safe.**

## Use it

Requires Python 3.12 and PowerShell: PowerShell 7 (`pwsh`) on any OS, or Windows PowerShell 5.1.

```powershell
uv tool install git+https://github.com/danielguillaumont/bomb-squad
bombsquad scan .\scripts                     # files or directories
Get-Clipboard | bombsquad scan -             # check a pasted command before running it
bombsquad scan . --format sarif -o bombsquad.sarif --fail-on high
```

Output is text, JSON or SARIF 2.1.0 (for GitHub code scanning). `--fail-on high|review|info` sets a non-zero exit code for CI.

## How it stays safe

The input is data, never code:

- It is parsed by `Parser.ParseInput` in a separate PowerShell process, in an empty working directory.
- `using module` and `using assembly` statements are blanked before parsing, because the parser opens the files they name.
- Names built from literals are folded by Bomb Squad's own code, never evaluated by PowerShell.

See the [threat model](docs/threat-model.md) for the rest, and [methodology](docs/methodology.md) for what each rule matches and its limits.

## Version 1

[Bomb Squad v1.0.0](https://github.com/danielguillaumont/bomb-squad/releases/tag/v1.0.0), the WinUI desktop inspector, is frozen at its tag and release.

v1 matched 12 PowerShell command names and `iex` by exact name. The constructs it missed are now regression tests in [`tests/test_powershell_rules.py`](tests/test_powershell_rules.py). Its six-finding sample still produces the same six findings.

**Built with:** Python · PowerShell AST · pytest · ruff · uv · GitHub Actions. [Development](docs/development.md).

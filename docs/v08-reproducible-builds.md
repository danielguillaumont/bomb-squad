# BOMB SQUAD v0.8 - NuGet dependency locking

## Status

Slice 2: local reproducibility checkpoint. Do not call this a public release until
Windows CI and an independent machine have verified the resulting distribution.

## Pinned Windows desktop dependencies

The versions below were resolved by the known-good Windows x64 publish probe on
2026-11-04. They are pinned as **exact version ranges**, not floating minimums.

| NuGet package | Exact version |
|---|---|
| Microsoft.Windows.SDK.BuildTools | 10.0.28000.2957 |
| Microsoft.Windows.SDK.BuildTools.WinApp | 0.7.1 |
| Microsoft.WindowsAppSDK | 2.6.5 |

These versions are *observed*, not claims that they are the newest versions.

## Lock-file generation and verification

`Directory.Build.props` opts all projects into checked-in `packages.lock.json` files.
Run the helper on **Windows** from the repository root:

```powershell
& .\scripts\Generate-v08-LockFiles.ps1
```

The `.slnx` deliberately omits `BombSquad.Desktop`. Therefore the helper restores
and verifies **both** `BombSquad.slnx` and `BombSquad.Desktop.csproj`.

Expected project-local lock files (6):

- `src/BombSquad.Core/packages.lock.json`
- `src/BombSquad.Rules/packages.lock.json`
- `src/BombSquad.Analysis/packages.lock.json`
- `src/BombSquad.Cli/packages.lock.json`
- `src/BombSquad.Desktop/packages.lock.json`
- `tests/BombSquad.Tests/packages.lock.json`

The helper also uses `dotnet restore --locked-mode` for each graph. A locked-mode
failure is a **stop condition**, not a reason to regenerate and ignore changes.

After successful generation, run the Release test suite, Desktop Debug build,
and the existing `Publish-v08-UnpackagedProbe.ps1`. Compare `git status` before
committing; verify that the only changes are this slice's project file, props,
document, helper script and six lock files. NuGet lock files must be committed.

## Scope and limitations

- This step locks NuGet dependencies; it does **not** lock the .NET SDK or Windows
  build tools on every developer/CI machine. CI SDK pinning and locked CI restores
  are a separate follow-up after the lock files are verified on Windows.
- Self-contained Windows publishing may select RID-specific targets. If a later
  `dotnet publish` changes a lock file, **stop and review the dependency graph**.
- Do not use `--force-evaluate` and `--locked-mode` together.
- Lock files do not certify the absence of package vulnerabilities, and pinning
  does not replace dependency-update reviews.
- Inspected PowerShell scripts are never executed by BOMB SQUAD.

# BOMB SQUAD v0.8 — Distribution baseline and test plan

**Status:** research and local probe. **NOT a signed installer or a verified public release.**

## Starting state

- Source baseline: v0.7 merged into `main`, commit `3fb41f3`.
- v0.8 branch: `feat/v08-windows-distribution`.
- Last user-verified baseline: 303 automated tests passing; WinUI Debug build working.
- `src/BombSquad.Desktop/BombSquad.Desktop.csproj` contains wildcard (`*`) package references to Microsoft.Windows.SDK.BuildTools, Microsoft.WindowsAppSDK, and Microsoft.Windows.SDK.BuildTools.WinApp.
- The same project sets `PublishTrimmed=true` and `PublishReadyToRun=true` for non-Debug builds. Do not use those defaults for the initial Release publish probe.
- Existing `docs/adr/ADR-002-desktop-distribution.md` validates publishing a separate feasibility app (DesktopProof), **not** clean-machine distribution of BOMB SQUAD.
- Existing `Package.appxmanifest` requests `systemAIModels`; this is not yet justified by known BOMB SQUAD features and must be reviewed before any MSIX distribution. It also carries placeholder publisher identity and should not be used unchanged for a public installer.

## v0.8 approach

1. **Slice 1** (this slice): publish an UNPACKAGED, multi-file Windows x64 folder with **both .NET and Windows App SDK self-contained**. Turn trimming, ReadyToRun, and single-file off via command-line MSBuild properties. Inspect the output and resolved package inventory. Keep everything in a temporary folder; do not change the app project.
2. **Slice 2:** pin and review precise, compatible NuGet package versions using the resolved inventory; repeat build/tests and publish. Do not guess versions from an unrelated template.
3. **Slice 3:** formalize an artifact-building script and GitHub Actions CI with release metadata, checksums and retained artifacts, no publishing to GitHub Releases yet.
4. **Slice 4:** independent Windows environment/clean-machine tests. Validate startup, assets, sample inspection, paste, file picker, JSON export and comparison. Document Windows/architecture requirements. Account for unsigned-binary warnings.
5. **Slice 5:** evaluate whether a signed installer/MSIX is practical; document signing/SmartScreen tradeoffs and cleanly close the milestone.

## Execute local probe

From PowerShell 5.1 at repository root after installing this slice:

```powershell
& .\scripts\Publish-v08-UnpackagedProbe.ps1
```

The script executes a project-scoped `dotnet publish` with:

- `--configuration Release --runtime win-x64 --self-contained true`
- `-p:WindowsPackageType=None`
- `-p:WindowsAppSDKSelfContained=true`
- `-p:PublishTrimmed=false`
- `-p:PublishReadyToRun=false`
- `-p:PublishSingleFile=false`
- `-p:GenerateAppxPackageOnBuild=false`

The script writes a unique `%TEMP%/BombSquad-v08-PublishProbe-.../publish` folder containing the EXE, libraries, native assets, and runtime. It prints exact paths, file count, total size and a `resolved-nuget-packages.txt` inventory beside the publish folder.

**Important:** use the `BombSquad.Desktop.exe` in the published folder for the actual launch test, not `dotnet run` (which uses development tooling). Never remove supposedly unneeded DLLs from this output.

## Local acceptance gates for Slice 1

- [ ] Repo starts clean on `feat/v08-windows-distribution`; only the new docs/script files are added.
- [ ] `dotnet test .\BombSquad.slnx -c Release` passes all 303 existing tests.
- [ ] `dotnet build .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug` succeeds.
- [ ] Unpackaged self-contained `dotnet publish` returns exit code 0; expected executable exists and is not empty.
- [ ] Direct-launch published EXE opens the real BOMB SQUAD UI; builtin sample shows 6 commands, 6 findings, 0 diagnostics.
- [ ] Paste, source view, exports and comparison spot-checks pass; any missing icon/resources are documented.
- [ ] Resolved dependency versions captured; no version-pinning changes yet.
- [ ] Do not claim clean-machine portability until tested on a separate target computer/VM.

## References

- https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/unpackage-winui-app
- https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/deploy-overview
- https://learn.microsoft.com/en-us/dotnet/core/deploying/trim-self-contained

## Constraints and security

- Inspected PowerShell remains inert input; no inspected script is executed by the BOMB SQUAD engine.
- A successful publish proves only an artifact was emitted, not that it starts outside the developer's environment.
- Folder-based distribution has no Windows package identity, built-in updater, or signing guarantees.
- Publish output may include licensed third-party components; review bundled dependencies and redistribution terms before release.

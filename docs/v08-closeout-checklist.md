# BOMB SQUAD v0.8 - Distribution Preview Closeout Checklist

**Branch:** `feat/v08-windows-distribution`  
**Latest previously validated commit:** `4f5cee5`  
**Scope:** Development preview milestone; no public Release, signed installer, or claims of clean-machine compatibility.

## Recorded evidence (already verified)

- [x] v0.7 merged to `main` via PR #8 (`3fb41f3`); v0.8 was branched cleanly.
- [x] v0.8 Slice 1: self-contained, unpackaged win-x64 publish; Windows branding files restored; developer-machine launch.
- [x] v0.8 Slice 2: NuGet package versions pinned and six lock files checked in; solution and WinUI desktop locked restores succeeded.
- [x] v0.8 Slice 3: ZIP/manifest/checksums generated; all 558 published files matched.
- [x] v0.8 Slice 4: Windows Distribution Preview GitHub Actions #1 passed; workflow artifact uploaded and downloaded; all 558 hashes matched.
- [x] Extracted GitHub-built EXE launched on the **developer** Windows PC; sample showed **6 commands / 6 findings / 0 parser diagnostics**.
- [x] Working tree was clean at commit `4f5cee5` before applying closeout edits.

## Final code/documentation gates (complete only after observed results)

- [ ] WinUI `MainPage.xaml` displays **v0.8 development** and desktop launches successfully.
- [ ] `actions/upload-artifact@v6` replaces `@v4` to use the supported Node.js 24 runtime; both hosted Windows workflows pass after push.
- [ ] `dotnet test .\BombSquad.slnx -c Release` passes with **at least 303 tests**, zero failures and zero skips.
- [ ] `dotnet build .\src\BombSquad.Desktop\BombSquad.Desktop.csproj -c Debug` succeeds.
- [ ] Local publishing, archive generation and full file-hash verification remain working; hosted distribution workflow uploads its ZIP, manifest, and SHA256SUMS.
- [ ] PR to `main` has been reviewed, checks passed, merged, and local `main` synchronized.
- [ ] End milestone with `git status -sb` clean, on `main`.

## Explicitly NOT TESTED (not v0.8 preview closeout blockers)

- **Fresh Windows x64 machine without developer tools:** NOT TESTED / DEFERRED. The intended VirtualBox guest was not provisioned because available RAM on the development laptop was inadequate. A second Windows PC or isolated VM is required prior to claiming clean-machine compatibility.
- **Code signing and installer:** NOT IMPLEMENTED / NOT TESTED. Windows SmartScreen/reputation prompts may occur for unsigned binaries; do not disable Windows defenses or misrepresent trust.
- **Public GitHub Release:** NOT PUBLISHED. A temporary GitHub workflow artifact is not an official release and may expire.
- **Authenticity:** SHA-256 compares files against an accompanying manifest; it does not prove the publisher's identity when all files were obtained from the same unauthenticated source.
- **Fully reproducible toolchain:** NuGet dependencies are locked, but .NET SDK 10.0.x is still a floating feature-channel version and GitHub Actions major tags are not immutable SHA pins.
- **Comprehensive detection:** Rule set remains partial; inspection is static and read-only; no findings does not establish safety; source PowerShell is never executed.

## Required pre-v1.0 release gate

Test the exact downloaded GitHub-built distribution on a clean Windows 11 x64 environment as a non-administrative user, without the .NET SDK or Windows App SDK development tools. Verify launch, taskbar/header icons, sample (6/6/0), paste-and-inspect, file opening, batch inspection, report export, comparison, relaunch, and any missing runtime prompts or OS warnings. Record screenshots/results, then resolve any blockers. Do not publish a trusted installer or advertise a production-ready v1.0 before compatibility and trust decisions are complete.

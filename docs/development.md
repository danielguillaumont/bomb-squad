# Development

## Setup

You need Python 3.12, [uv](https://docs.astral.sh/uv/), and PowerShell: `pwsh` 7, or Windows PowerShell 5.1 on Windows. CI runs on Linux, macOS and Windows with pwsh 7.

```powershell
uv sync --locked --python 3.12
uv run --locked pytest
uv run --locked ruff check .
uvx --from actionlint-py actionlint   # after any workflow change
uv run bombsquad scan samples\example.ps1
```

Set `BOMBSQUAD_POWERSHELL` to pick a specific PowerShell executable.

## Layout

| Path | What it does |
|---|---|
| `src/bombsquad/cli.py` | The `bombsquad scan` and `bombsquad rules` commands |
| `src/bombsquad/scan.py` | Finds files and builds the report |
| `src/bombsquad/inventory.py`, `discovery.py` | Finds entry points and the files they run |
| `src/bombsquad/repo/` | Workflows and actions, editor tasks and dev containers, git hooks, agent files and MCP configs, their rules, and the YAML, JSONC and Markdown readers |
| `src/bombsquad/code/` | The JavaScript, Python and shell analyzers and their rules |
| `src/bombsquad/powershell/dump_ast.ps1` | Parses PowerShell and writes out the syntax tree. It never evaluates input. |
| `src/bombsquad/powershell/parser.py` | Blanks `using` statements, runs the dumper, and reads its output |
| `src/bombsquad/powershell/names.py` | Aliases, native tools, parameter prefixes, registry paths |
| `src/bombsquad/powershell/analyze.py` | Applies the rules and follows decoded content |
| `src/bombsquad/powershell/rules.py` | The rule catalogue |
| `src/bombsquad/registry.py`, `archive.py`, `diff.py`, `source.py` | `bombsquad diff`: registry metadata and hash checks, safe unpacking, the comparison, and the check against the GitHub source and tag record |
| `src/bombsquad/lockfiles.py`, `actionrefs.py`, `gate.py`, `action.yml` | `bombsquad gate`: pinned versions from lockfiles, action references and their review, the pull request report and its comment, and the GitHub Action |
| `src/bombsquad/sarif.py`, `text_report.py` | Output formats |
| `src/bombsquad/detonate/` | `bombsquad detonate`: the sandbox images, the sink, fake credentials, the strace reader and the comparison with the static scan |
| `benchmark/` | The accuracy benchmark against GuardDog. It runs only in `.github/workflows/benchmark.yml`, on Linux CI. |
| `watch/` | The daily watch: new releases of popular packages, diffed and queued for review; the review step, the flag log and defusal record, and the site and feed built from them |
| `scripts/detonation-vm.ps1`, `detonation-vm.sh` | A disposable Azure VM for detonating malicious samples, and its boot script |

## Detonation VM

The benchmark detonates live malicious samples (`detonate` input `all`) only on a disposable virtual machine. Neither GitHub's shared runners nor a development machine is used. The job refuses to start anywhere else, so a run with `all` waits until such a VM is registered.

### With Azure, in one command

`scripts/detonation-vm.ps1` does the whole run with the signed-in Azure CLI and GitHub CLI, from Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\scripts\detonation-vm.ps1 run
```

1. It checks that workflows from fork pull requests need approval for all outside contributors, and that no earlier detonation VM or runner is left.
2. It shows the subscription, location and VM size, and asks you to type `yes`.
3. It creates a resource group with one Ubuntu 24.04 VM (`Standard_D4s_v5` by default) and nothing else. The VM has no managed identity and no inbound rules. Its only outbound traffic to the internet is TCP 80 and 443. Azure deallocates it after `-MaxHours` (7 by default) even if the script has stopped.
4. At boot, `scripts/detonation-vm.sh` installs Docker, writes `/etc/bombsquad/disposable-vm`, and registers a runner that takes one job and unregisters. The runner is downloaded at a pinned version and checked against its SHA-256. It may update itself from GitHub's releases if GitHub no longer accepts that version.
5. The script dispatches the benchmark with `detonate=all` and waits for it.
6. When the run ends, fails or is interrupted, it cancels the run if it has not finished and deletes the resource group and the runner.

If the window closes during a run, delete what is left:

```powershell
.\scripts\detonation-vm.ps1 down
```

Before the first run:

- Use a subscription that holds nothing else of value, and check that its terms allow running malware samples for research in your own VM.
- Set the fork approval policy, once: `gh api --method PUT repos/danielguillaumont/bomb-squad/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors`.
- The run is billed while the VM exists. `-DryRun` prints what would be done without calling Azure or GitHub.

What it does not do:

- Azure filters outbound traffic by address and port, not by host name, so the VM itself can reach any web server. The packages reach only the sink, on an internal Docker network.
- The runner's registration token is passed in the VM's custom data. The boot script removes the copies it knows of once the runner is registered, and the token expires an hour after it was made.
- The VM can reach Azure's instance metadata service. With no managed identity, that gives descriptions of the VM and no credentials.

### Elsewhere

1. **Create a fresh Linux x86-64 VM** for each run, on a cloud account or a host that holds nothing else of value.
   - It holds no credentials and no cloud role. Turn off the instance metadata service, or give the VM no instance role.
   - It has no folders shared with another machine.
   - Its outbound traffic is limited to what the job fetches: GitHub, the npm and PyPI registries, Docker Hub for the pinned base images, and the Debian mirror the images install strace from. Where only addresses and ports can be filtered, allow TCP 80 and 443 and nothing else. The packages themselves reach only the sink, on an internal Docker network.
2. **Install Docker Engine**, then mark the VM as disposable: `sudo mkdir -p /etc/bombsquad && sudo touch /etc/bombsquad/disposable-vm`. The workflow checks for this file. `scripts/detonation-vm.sh` does this and the next step on any Ubuntu VM with cloud-init.
3. **In the repository's settings** (Actions, General), require approval for workflows from fork pull requests by all outside contributors. Any workflow file in a fork could otherwise ask for the runner's label while it is registered.
4. **Register the VM as an ephemeral runner** right before dispatching the run, with the labels `self-hosted`, `linux`, `x64` and `bombsquad-detonation`. Follow GitHub's instructions for adding a self-hosted runner, and pass `--ephemeral` to `config.sh` so that the runner takes one job and unregisters.
5. **Dispatch the benchmark** with `detonate` set to `all`.
6. **Destroy the VM** when the run ends, whatever its outcome. Never reuse it, and never copy files off it. The results reach GitHub as the run's artifact.

The job's token can only read the repository and upload the run's artifact. A package that escaped its container could use that token while the job runs, and it could reach whatever the VM's outbound rules allow. This is why the VM is disposable and holds nothing else. Bomb Squad's own scan reports the job as running on a self-hosted runner (BS-GHA-005). That is the one finding this repository's workflows have, and it is expected.

## Samples that look like malware

Antivirus software quarantines files that contain download cradles, encoded commands or AMSI internals. It also blocks tools from reading output that prints them.

- Test samples like these are stored ROT13-encoded in `tests/test_powershell_rules.py` and decoded in memory.
- Assertions compare rule IDs only, so a failing test does not print a sample.
- Never write such samples to disk in plain text. Never add an antivirus exclusion to make a test pass.

<#
.SYNOPSIS
Runs the benchmark with detonate=all on a throwaway Azure VM, then deletes the VM.

.DESCRIPTION
`run` creates a resource group that holds one Ubuntu VM and nothing else. The VM has no
managed identity, accepts no inbound connections, and can send only HTTP and HTTPS out. It
registers itself as an ephemeral GitHub Actions runner (scripts/detonation-vm.sh). The script
then dispatches the benchmark with detonate=all, waits for it, and deletes the resource group
whatever the outcome. `down` deletes every resource group this script made, and the runners
it registered, in case a run was interrupted.

Uses the signed-in Azure CLI (az) and GitHub CLI (gh). It never installs, runs or opens a
package on this machine. See docs/development.md#detonation-vm.

.EXAMPLE
.\scripts\detonation-vm.ps1 run

.EXAMPLE
.\scripts\detonation-vm.ps1 down
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("run", "down")]
    [string] $Command = "run",
    # A region the subscription allows; Azure for Students allows only a few.
    [string] $Location = "canadacentral",
    # 4 vCPUs and 16 GB. Azure for Students allows 4 cores of the DSv4 family, and none of DSv5.
    [string] $Size = "Standard_D4s_v4",
    # Azure deallocates the VM after this long even if this script is no longer running.
    [ValidateRange(1, 24)]
    [int] $MaxHours = 7,
    [string] $Ref = "main",
    [string] $Repo = "danielguillaumont/bomb-squad",
    # Skip the confirmation prompt.
    [switch] $Yes,
    # Print what would be done, and the boot script, without calling Azure or GitHub.
    [switch] $DryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$TagName = "bombsquad"
$TagValue = "detonation"
$RunnerPrefix = "bombsquad-detonation-"
$Workflow = "benchmark.yml"
$BootScript = Join-Path $PSScriptRoot "detonation-vm.sh"

function Invoke-Tool {
    # Runs az or gh, and nothing else, with an argument list and returns its standard output
    # as text.
    param([ValidateSet("az", "gh")] [string] $Tool, [string[]] $Arguments,
        [switch] $AllowFailure)
    if ($DryRun) {
        Write-Host "would run: $Tool $($Arguments -join ' ')"
        return ""
    }
    $output = & $Tool @Arguments
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) {
        throw "$Tool $($Arguments[0]) $($Arguments[1]) failed with exit code $LASTEXITCODE"
    }
    return ($output -join "`n")
}

function Assert-Tools {
    foreach ($tool in "az", "gh") {
        if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
            throw "$tool is not installed. See docs/development.md#detonation-vm."
        }
    }
}

function Get-DetonationGroups {
    $names = Invoke-Tool az @("group", "list", "--tag", "$TagName=$TagValue", "--query",
        "[].name", "--output", "tsv")
    return @($names -split "`n" | Where-Object { $_.Trim() })
}

function Get-DetonationRunners {
    # Filtered here, not with --jq: Windows PowerShell 5.1 drops quotes inside arguments.
    $lines = Invoke-Tool gh @("api", "repos/$Repo/actions/runners", "--paginate", "--jq",
        ".runners[] | [.id, .name, .status] | @tsv")
    return @($lines -split "`n" | Where-Object { $_.Trim() } | ForEach-Object {
            $id, $name, $status = $_ -split "`t"
            [pscustomobject]@{ Id = $id; Name = $name; Status = "$status".Trim() }
        } | Where-Object { $_.Name -like "$RunnerPrefix*" })
}

function Remove-Detonation {
    param([string[]] $Groups)
    foreach ($group in $Groups) {
        Write-Host "Deleting resource group $group ..."
        Invoke-Tool az @("group", "delete", "--name", $group, "--yes") | Out-Null
    }
    # An ephemeral runner removes itself after its job. One whose VM went first is left.
    foreach ($runner in Get-DetonationRunners) {
        Write-Host "Removing runner $($runner.Name) ..."
        Invoke-Tool gh @("api", "--method", "DELETE",
            "repos/$Repo/actions/runners/$($runner.Id)") -AllowFailure | Out-Null
    }
}

function Write-BootScript {
    param([string] $Path, [string] $RunnerName, [string] $Token)
    $text = [IO.File]::ReadAllText($BootScript) -replace "`r`n", "`n"
    $text = $text.Replace("__REPO_URL__", "https://github.com/$Repo")
    $text = $text.Replace("__RUNNER_NAME__", $RunnerName).Replace("__TOKEN__", $Token)
    [IO.File]::WriteAllText($Path, $text, (New-Object Text.UTF8Encoding $false))
}

function Wait-Runner {
    # The runner's name, once it is online; it registers a few minutes after the VM starts.
    param([string] $RunnerName, [int] $Minutes = 20)
    if ($DryRun) { return }
    $deadline = (Get-Date).AddMinutes($Minutes)
    while ((Get-Date) -lt $deadline) {
        $runner = Get-DetonationRunners | Where-Object { $_.Name -eq $RunnerName }
        if ($runner) {
            Write-Host "Runner $RunnerName is $($runner.Status)."
            return
        }
        Start-Sleep -Seconds 30
    }
    throw "The VM did not register its runner within $Minutes minutes."
}

function Find-Run {
    param([datetime] $Since)
    if ($DryRun) { return $null }
    for ($i = 0; $i -lt 20; $i++) {
        $json = Invoke-Tool gh @("run", "list", "--repo", $Repo, "--workflow", $Workflow,
            "--event", "workflow_dispatch", "--limit", "5", "--json", "databaseId,createdAt,url")
        $run = $json | ConvertFrom-Json | Where-Object {
            ([datetime]$_.createdAt).ToUniversalTime() -ge $Since.AddMinutes(-1)
        } | Select-Object -First 1
        if ($run) { return $run }
        Start-Sleep -Seconds 5
    }
    throw "The dispatched benchmark run did not appear."
}

function Start-Detonation {
    Assert-Tools
    if (-not (Test-Path $BootScript)) { throw "Missing $BootScript" }

    if (-not $DryRun) {
        $account = Invoke-Tool az @("account", "show", "--query", "[name, id]", "--output",
            "tsv")
        $subscription = ($account -split "`n")[0]
        $policy = Invoke-Tool gh @("api",
            "repos/$Repo/actions/permissions/fork-pr-contributor-approval", "--jq",
            ".approval_policy")
        if ($policy.Trim() -ne "all_external_contributors") {
            throw ("Workflows from fork pull requests must need approval for all outside " +
                "contributors while the runner is registered. Set it in the repository's " +
                "Actions settings, or run: gh api --method PUT " +
                "repos/$Repo/actions/permissions/fork-pr-contributor-approval " +
                "-f approval_policy=all_external_contributors")
        }
        # Subscriptions such as Azure for Students allow only some regions, by policy.
        $allowed = Invoke-Tool az @("policy", "assignment", "list", "--query",
            "[].parameters.listOfAllowedLocations.value[]", "--output", "tsv")
        $regions = @($allowed -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
        if ($regions.Count -gt 0 -and $regions -notcontains $Location) {
            throw "The subscription does not allow $Location. Pass -Location with one of: $($regions -join ', ')"
        }
        $left = @(Get-DetonationGroups)
        if ($left.Count -gt 0) {
            throw "A detonation VM is still there ($($left -join ', ')). Run: .\scripts\detonation-vm.ps1 down"
        }
        if (@(Get-DetonationRunners | Where-Object { $_.Status -eq "online" }).Count -gt 0) {
            throw "A detonation runner is already online. Run: .\scripts\detonation-vm.ps1 down"
        }
    }
    else {
        $subscription = "(dry run)"
    }

    Write-Host ""
    Write-Host "This creates a VM that detonates live malicious packages, and is billed while it exists:"
    Write-Host "  Azure subscription: $subscription"
    Write-Host "  Location and size:  $Location, $Size"
    Write-Host "  Deallocated after:  $MaxHours hours at most, deleted when the run ends"
    Write-Host "  Benchmark:          $Repo $Workflow at $Ref, detonate=all"
    Write-Host "It goes in a new resource group of its own; nothing else in the subscription is changed."
    if (-not $Yes -and -not $DryRun) {
        if ((Read-Host "Type yes to go on") -ne "yes") { Write-Host "Stopped."; return }
    }

    $id = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmm") + "-" + (Get-Random -Maximum 10000)
    $group = "bombsquad-detonation-$id"
    $runnerName = "$RunnerPrefix$id"
    $work = Join-Path ([IO.Path]::GetTempPath()) "bombsquad-$id"
    New-Item -ItemType Directory -Path $work | Out-Null
    $created = $false
    $run = $null
    try {
        # The VM needs an admin key to be created. Nothing can connect to it, so the key is
        # thrown away straight after.
        $key = Join-Path $work "key"
        if ($DryRun) { Set-Content -Path "$key.pub" -Value "ssh-ed25519 DRYRUN" }
        else {
            # The passphrase does not matter: only the public key is used.
            & ssh-keygen -q -t ed25519 -N '""' -f $key | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "ssh-keygen failed" }
        }
        $publicKey = (Get-Content -Raw "$key.pub").Trim()

        $token = "DRYRUN"
        if (-not $DryRun) {
            $token = (Invoke-Tool gh @("api", "--method", "POST",
                    "repos/$Repo/actions/runners/registration-token", "--jq", ".token")).Trim()
        }
        $boot = Join-Path $work "boot.sh"
        Write-BootScript -Path $boot -RunnerName $runnerName -Token $token
        if ($DryRun) { Write-Host "boot script:"; Get-Content $boot | Write-Host }

        # A new subscription has to have these services turned on once. Registering them
        # changes nothing that already exists.
        foreach ($provider in "Microsoft.Compute", "Microsoft.Network") {
            Invoke-Tool az @("provider", "register", "--namespace", $provider, "--wait") | Out-Null
        }

        $now = (Get-Date).ToUniversalTime()
        Invoke-Tool az @("group", "create", "--name", $group, "--location", $Location,
            "--tags", "$TagName=$TagValue", "created=$($now.ToString('o'))", "--output",
            "none") | Out-Null
        $created = $true

        # No inbound rules: Azure's default rules refuse everything from the internet.
        # Outbound to the internet: HTTP and HTTPS only. Azure DNS is not on the internet.
        Invoke-Tool az @("network", "nsg", "create", "--resource-group", $group, "--name",
            "detonation-nsg", "--output", "none") | Out-Null
        Invoke-Tool az @("network", "nsg", "rule", "create", "--resource-group", $group,
            "--nsg-name", "detonation-nsg", "--name", "web-out", "--priority", "100",
            "--direction", "Outbound", "--access", "Allow", "--protocol", "Tcp",
            "--destination-address-prefixes", "Internet", "--destination-port-ranges", "80",
            "443", "--output", "none") | Out-Null
        Invoke-Tool az @("network", "nsg", "rule", "create", "--resource-group", $group,
            "--nsg-name", "detonation-nsg", "--name", "no-other-out", "--priority", "4000",
            "--direction", "Outbound", "--access", "Deny", "--protocol", "*",
            "--destination-address-prefixes", "Internet", "--destination-port-ranges", "*",
            "--output", "none") | Out-Null

        Write-Host "Creating the VM ..."
        Invoke-Tool az @("vm", "create", "--resource-group", $group, "--name", "detonation",
            "--image", "Ubuntu2404", "--size", $Size, "--admin-username", "bombsquad",
            "--ssh-key-values", $publicKey, "--custom-data", $boot, "--nsg", "detonation-nsg",
            "--public-ip-sku", "Standard", "--os-disk-size-gb", "64",
            "--os-disk-delete-option", "Delete", "--nic-delete-option", "Delete",
            "--tags", "$TagName=$TagValue", "--output", "none") | Out-Null
        Remove-Item -Force $key, "$key.pub", $boot -ErrorAction SilentlyContinue

        $stop = $now.AddHours($MaxHours).ToString("HHmm")
        Invoke-Tool az @("vm", "auto-shutdown", "--resource-group", $group, "--name",
            "detonation", "--time", $stop, "--output", "none") | Out-Null

        Wait-Runner -RunnerName $runnerName
        $dispatched = (Get-Date).ToUniversalTime()
        Invoke-Tool gh @("workflow", "run", $Workflow, "--repo", $Repo, "--ref", $Ref,
            "-f", "detonate=all") | Out-Null
        $run = Find-Run -Since $dispatched
        if ($run) {
            Write-Host "Benchmark run: $($run.url)"
            Write-Host "If this window closes before it ends, run: .\scripts\detonation-vm.ps1 down"
            # Not captured, so its progress shows as it goes.
            & gh run watch "$($run.databaseId)" --repo $Repo --interval 120 --compact
        }
    }
    finally {
        if ($run -and -not $DryRun) {
            $status = Invoke-Tool gh @("run", "view", "$($run.databaseId)", "--repo", $Repo,
                "--json", "status", "--jq", ".status") -AllowFailure
            if ($status.Trim() -ne "completed") {
                Write-Host "Cancelling the run, which has not finished ..."
                Invoke-Tool gh @("run", "cancel", "$($run.databaseId)", "--repo", $Repo) -AllowFailure | Out-Null
            }
        }
        if ($created) { Remove-Detonation -Groups @($group) }
        Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
        if ($run) { Write-Host "Done. Results: $($run.url)" }
    }
}

switch ($Command) {
    "run" { Start-Detonation }
    "down" {
        Assert-Tools
        Remove-Detonation -Groups (Get-DetonationGroups)
        Write-Host "No detonation VM or runner is left."
    }
}

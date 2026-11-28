<#
.SYNOPSIS
Runs the benchmark with detonate=all on a throwaway Azure VM, then deletes the VM.

.DESCRIPTION
`check` reads, without changing anything, what `run` later reads from GitHub. It then
asks Azure to validate the VM request, size by size and region by region, without
creating a VM; it creates only an empty resource group and firewall for each region it
tries, and deletes them. In the first accepted one it also tries the deadline below. `run`
makes the same check, then creates the VM in the first place Azure accepts. It creates a
resource group that holds one Ubuntu VM and its deadline. The VM has no managed identity,
accepts no inbound connections, and can send only HTTP and HTTPS out. It registers itself as
an ephemeral GitHub Actions runner (scripts/detonation-vm.sh), and powers off when its one
job ends. The script then dispatches the benchmark with detonate=all, waits for it, and
deletes the resource group whatever the outcome.

The deadline (scripts/detonation-deadline.json) deletes the group from Azure, so the VM goes
even if this script or the machine running it stops. It is a Logic App with its own
identity, allowed only that resource group. Every 5 minutes it deletes the group if the VM
is powered off or $MaxHours have passed. `down` deletes every resource group this script
made, and the runners it registered, in case a run was interrupted.

Uses the signed-in Azure CLI (az) and GitHub CLI (gh). It never installs, runs or opens a
package on this machine. See docs/development.md#detonation-vm.

.EXAMPLE
.\scripts\detonation-vm.ps1 check

.EXAMPLE
.\scripts\detonation-vm.ps1 run

.EXAMPLE
.\scripts\detonation-vm.ps1 down
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("run", "check", "down")]
    [string] $Command = "run",
    # Regions to try, in order, separated by commas. Those the subscription's policy does not
    # allow are skipped; Azure for Students allows only a few.
    [string[]] $Location = @("canadacentral", "westus", "northcentralus", "norwayeast",
        "belgiumcentral"),
    # Sizes to try in each region, in order: 4 vCPUs and 16 GB, in families that Azure for
    # Students gives 4 cores of. It gives none of DSv5.
    [string[]] $Size = @("Standard_D4s_v4", "Standard_D4as_v4", "Standard_D4ds_v4",
        "Standard_D4s_v3", "Standard_D4_v4"),
    # Azure deletes the VM after this long even if this script is no longer running.
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
$DeadlineTemplate = Join-Path $PSScriptRoot "detonation-deadline.json"
# The full image name: the CLI's short aliases need a download and differ between versions.
$Image = "Canonical:ubuntu-24_04-lts:server:latest"

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
    param([switch] $AllowFailure)
    # Filtered here, not with --jq: Windows PowerShell 5.1 drops quotes inside arguments.
    $lines = Invoke-Tool gh @("api", "repos/$Repo/actions/runners", "--paginate", "--jq",
        ".runners[] | [.id, .name, .status] | @tsv") -AllowFailure:$AllowFailure
    return @($lines -split "`n" | Where-Object { $_.Trim() } | ForEach-Object {
            $id, $name, $status = $_ -split "`t"
            [pscustomobject]@{ Id = $id; Name = $name; Status = "$status".Trim() }
        } | Where-Object { $_.Name -like "$RunnerPrefix*" })
}

function Remove-Detonation {
    param([string[]] $Groups)
    # Each step goes on when one fails, such as on a dropped connection; `down` can be run
    # again to finish.
    foreach ($group in $Groups) {
        Write-Host "Deleting resource group $group ..."
        Invoke-Tool az @("group", "delete", "--name", $group, "--yes") -AllowFailure | Out-Null
        if (-not $DryRun -and $LASTEXITCODE -ne 0) {
            Write-Warning "Could not delete $group. Run: .\scripts\detonation-vm.ps1 down"
        }
    }
    # An ephemeral runner removes itself after its job. One whose VM went first is left.
    foreach ($runner in Get-DetonationRunners -AllowFailure) {
        Write-Host "Removing runner $($runner.Name) ..."
        Invoke-Tool gh @("api", "--method", "DELETE",
            "repos/$Repo/actions/runners/$($runner.Id)") -AllowFailure | Out-Null
    }
}

function Write-BootScript {
    param([string] $Path, [string] $RunnerName, [string] $Token)
    $minutes = [string]($MaxHours * 60)
    $text = [IO.File]::ReadAllText($BootScript) -replace "`r`n", "`n"
    $text = $text.Replace("__REPO_URL__", "https://github.com/$Repo")
    $text = $text.Replace("__RUNNER_NAME__", $RunnerName).Replace("__TOKEN__", $Token)
    $text = $text.Replace("__MAX_MINUTES__", $minutes)
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
    # The latest dispatched benchmark run created after $Since, or $null after $Attempts tries.
    param([datetime] $Since, [int] $Attempts = 20)
    if ($DryRun) { return $null }
    for ($i = 0; $i -lt $Attempts; $i++) {
        $json = Invoke-Tool gh @("run", "list", "--repo", $Repo, "--workflow", $Workflow,
            "--event", "workflow_dispatch", "--limit", "5", "--json", "databaseId,createdAt,url")
        # Windows PowerShell 5.1 passes a JSON array down the pipeline as one object, so the
        # runs are enumerated first.
        $runs = $json | ConvertFrom-Json
        $run = $runs | ForEach-Object { $_ } | Where-Object {
            ([datetime]$_.createdAt).ToUniversalTime() -ge $Since.AddMinutes(-1)
        } | Select-Object -First 1
        if ($run) { return $run }
        if ($i -lt $Attempts - 1) { Start-Sleep -Seconds 5 }
    }
    return $null
}

function Get-RunStatus {
    param([string] $RunId)
    $status = Invoke-Tool gh @("run", "view", $RunId, "--repo", $Repo, "--json", "status",
        "--jq", ".status") -AllowFailure
    return "$status".Trim()
}

function Assert-ForkApproval {
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
}

function Test-GitHub {
    # The GitHub calls `run` makes once the VM is up, made read-only against the latest
    # benchmark run that already exists. It dispatches nothing.
    Assert-ForkApproval
    $yaml = Invoke-Tool gh @("workflow", "view", $Workflow, "--repo", $Repo, "--ref", $Ref,
        "--yaml")
    if ($yaml -notmatch "(?m)^\s+detonate:") {
        throw "$Workflow at $Ref has no detonate input."
    }
    Get-DetonationRunners | Out-Null
    $run = Find-Run -Since (Get-Date).ToUniversalTime().AddDays(-90) -Attempts 1
    if (-not $run) {
        Write-Host "GitHub: no dispatched benchmark run in the last 90 days to check against."
        return
    }
    $status = Get-RunStatus -RunId "$($run.databaseId)"
    if (-not $status) { throw "Could not read the status of benchmark run $($run.databaseId)." }
    Write-Host "GitHub: the workflow, the runners and benchmark run $($run.databaseId) ($status) can be read."
}

function Split-List {
    # `-Location a,b` from another shell arrives as one string.
    param([string[]] $Values)
    return @($Values | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } |
            Where-Object { $_ })
}

function Get-AllowedLocations {
    # Subscriptions such as Azure for Students allow only some regions, by policy.
    $wanted = Split-List $Location
    if ($DryRun) { return $wanted }
    $allowed = Invoke-Tool az @("policy", "assignment", "list", "--query",
        "[].parameters.listOfAllowedLocations.value[]", "--output", "tsv")
    $regions = @($allowed -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($regions.Count -eq 0) { return $wanted }
    $kept = @($wanted | Where-Object { $regions -contains $_ })
    if ($kept.Count -eq 0) {
        throw "The subscription allows none of $($wanted -join ', '). It allows: $($regions -join ', ')"
    }
    return $kept
}

function Register-Providers {
    # A new subscription has to have these services turned on once. Registering them changes
    # nothing that already exists.
    foreach ($provider in "Microsoft.Compute", "Microsoft.Network", "Microsoft.Logic") {
        Invoke-Tool az @("provider", "register", "--namespace", $provider, "--wait") | Out-Null
    }
}

function Set-Deadline {
    # Deploys the deadline into the group: it deletes the group once the VM is powered off
    # or the time has passed. $true when Azure accepted it. Creating its role assignment
    # needs the right to assign roles, which a subscription's owner has.
    param([string] $Group, [datetime] $DeleteAfter)
    $after = $DeleteAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Invoke-Tool az @("deployment", "group", "create", "--resource-group", $Group, "--name",
        "detonation-deadline", "--template-file", $DeadlineTemplate, "--parameters",
        "deleteAfter=$after", "--output", "none") -AllowFailure | Out-Null
    return ($DryRun -or $LASTEXITCODE -eq 0)
}

function New-NetworkGroup {
    # The resource group and the firewall the VM gets. Both are free while there is no VM.
    param([string] $Group, [string] $Where)
    Invoke-Tool az @("group", "create", "--name", $Group, "--location", $Where,
        "--tags", "$TagName=$TagValue", "created=$((Get-Date).ToUniversalTime().ToString('o'))",
        "--output", "none") | Out-Null
    # No inbound rules: Azure's default rules refuse everything from the internet.
    # Outbound to the internet: HTTP and HTTPS only. Azure DNS is not on the internet.
    Invoke-Tool az @("network", "nsg", "create", "--resource-group", $Group, "--name",
        "detonation-nsg", "--location", $Where, "--output", "none") | Out-Null
    Invoke-Tool az @("network", "nsg", "rule", "create", "--resource-group", $Group,
        "--nsg-name", "detonation-nsg", "--name", "web-out", "--priority", "100",
        "--direction", "Outbound", "--access", "Allow", "--protocol", "Tcp",
        "--destination-address-prefixes", "Internet", "--destination-port-ranges", "80",
        "443", "--output", "none") | Out-Null
    Invoke-Tool az @("network", "nsg", "rule", "create", "--resource-group", $Group,
        "--nsg-name", "detonation-nsg", "--name", "no-other-out", "--priority", "4000",
        "--direction", "Outbound", "--access", "Deny", "--protocol", "*",
        "--destination-address-prefixes", "Internet", "--destination-port-ranges", "*",
        "--output", "none") | Out-Null
}

function Get-VmArguments {
    param([string] $Group, [string] $Where, [string] $VmSize, [string] $PublicKey,
        [string] $Boot)
    return @("vm", "create", "--resource-group", $Group, "--name", "detonation",
        "--location", $Where, "--image", $Image, "--size", $VmSize,
        "--admin-username", "bombsquad", "--ssh-key-values", $PublicKey,
        "--custom-data", $Boot, "--nsg", "detonation-nsg", "--public-ip-sku", "Standard",
        "--os-disk-size-gb", "64", "--os-disk-delete-option", "Delete",
        "--nic-delete-option", "Delete", "--tags", "$TagName=$TagValue", "--output", "none")
}

function Find-Placement {
    # The first region and size for which Azure validates the full VM request, quota and
    # capacity included, without creating the VM. With -Keep, that region's resource group
    # and firewall are kept for the VM; every other group made here is deleted.
    param([string] $Id, [string] $PublicKey, [string] $Boot, [switch] $Keep)
    $tried = @()
    foreach ($where in Get-AllowedLocations) {
        $group = "bombsquad-detonation-$Id-$where"
        Write-Host "Checking $where ..."
        New-NetworkGroup -Group $group -Where $where
        foreach ($vmSize in Split-List $Size) {
            $arguments = (Get-VmArguments $group $where $vmSize $PublicKey $Boot) + "--validate"
            if ($DryRun) {
                Invoke-Tool az $arguments | Out-Null
                return [pscustomobject]@{ Location = $where; Size = $vmSize; Group = $group }
            }
            # Windows PowerShell 5.1 turns a native command's error output into exceptions
            # when it is redirected and errors stop the script.
            $previous = $ErrorActionPreference
            $ErrorActionPreference = "Continue"
            try {
                $errors = & az @arguments 2>&1 | Out-String
                $code = $LASTEXITCODE
            }
            finally { $ErrorActionPreference = $previous }
            if ($code -eq 0) {
                Write-Host "  $vmSize : accepted"
                if (-not $Keep) { Remove-Detonation -Groups @($group) }
                return [pscustomobject]@{ Location = $where; Size = $vmSize; Group = $group }
            }
            $codes = @([regex]::Matches($errors, "\((\w+)\)") | ForEach-Object { $_.Groups[1].Value } |
                    Where-Object { $_.Length -gt 1 -and $_ -notin "InvalidTemplateDeployment" } | Select-Object -Unique)
            $reason = if ($codes.Count -gt 0) { $codes -join ", " } else { "refused" }
            Write-Host "  $vmSize : $reason"
            $tried += "$vmSize in $where ($reason)"
        }
        Remove-Detonation -Groups @($group)
    }
    Write-Host "Nothing was accepted. Tried: $($tried -join '; ')"
    return $null
}

function New-Key {
    # The VM needs an admin key to be created. Nothing can connect to it, so the key is thrown
    # away straight after.
    param([string] $Work)
    $key = Join-Path $Work "key"
    if ($DryRun) { Set-Content -Path "$key.pub" -Value "ssh-ed25519 DRYRUN" }
    else {
        # The passphrase does not matter: only the public key is used.
        & ssh-keygen -q -t ed25519 -N '""' -f $key | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "ssh-keygen failed" }
    }
    return (Get-Content -Raw "$key.pub").Trim()
}

function Assert-Clean {
    $left = @(Get-DetonationGroups)
    if ($left.Count -gt 0) {
        throw "A detonation resource group is still there ($($left -join ', ')). Run: .\scripts\detonation-vm.ps1 down"
    }
}

function Test-Placement {
    # `check`: what `run` would pick, without creating a VM or registering a runner.
    Assert-Tools
    if (-not $DryRun) {
        Assert-Clean
        Test-GitHub
    }
    Register-Providers
    $id = "check-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmm")
    $work = Join-Path ([IO.Path]::GetTempPath()) "bombsquad-$id"
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        $publicKey = New-Key -Work $work
        $boot = Join-Path $work "boot.sh"
        Write-BootScript -Path $boot -RunnerName "check" -Token "CHECK"
        $placement = Find-Placement -Id $id -PublicKey $publicKey -Boot $boot -Keep
        if ($placement) {
            # The deadline, in the empty group: there is no VM for it to act on, and the
            # group is deleted straight after.
            $deadline = Set-Deadline -Group $placement.Group -DeleteAfter (Get-Date).AddHours($MaxHours)
            Remove-Detonation -Groups @($placement.Group)
        }
    }
    finally {
        Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    }
    if (-not $placement) { throw "No region and size was accepted; nothing was created." }
    if ($deadline) { Write-Host "Azure accepted the deadline that deletes the VM if this script stops." }
    else {
        Write-Warning ("Azure did not accept the deadline (it needs the right to assign roles " +
            "in the subscription). run would go on without it: if the script stops, the VM " +
            "is billed until .\scripts\detonation-vm.ps1 down deletes it.")
    }
    Write-Host "run would create a $($placement.Size) VM in $($placement.Location). Nothing is left."
}

function Start-Detonation {
    Assert-Tools
    if (-not (Test-Path $BootScript)) { throw "Missing $BootScript" }

    if (-not $DryRun) {
        $account = Invoke-Tool az @("account", "show", "--query", "[name, id]", "--output",
            "tsv")
        $subscription = ($account -split "`n")[0]
        Assert-Clean
        Test-GitHub
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
    Write-Host "  Where:              the first of $((Split-List $Location) -join ', ') that Azure accepts"
    Write-Host "  Size:               the first of $((Split-List $Size) -join ', ') that Azure accepts"
    Write-Host "  Deleted:            when the run ends, or by Azure once the VM powers off or after $MaxHours hours"
    Write-Host "  Benchmark:          $Repo $Workflow at $Ref, detonate=all"
    Write-Host "It goes in a new resource group of its own; nothing else in the subscription is changed."
    if (-not $Yes -and -not $DryRun) {
        if ((Read-Host "Type yes to go on") -ne "yes") { Write-Host "Stopped."; return }
    }

    $id = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmm") + "-" + (Get-Random -Maximum 10000)
    $runnerName = "$RunnerPrefix$id"
    $work = Join-Path ([IO.Path]::GetTempPath()) "bombsquad-$id"
    New-Item -ItemType Directory -Path $work | Out-Null
    $group = $null
    $run = $null
    try {
        $publicKey = New-Key -Work $work
        $token = "DRYRUN"
        if (-not $DryRun) {
            $token = (Invoke-Tool gh @("api", "--method", "POST",
                    "repos/$Repo/actions/runners/registration-token", "--jq", ".token")).Trim()
        }
        $boot = Join-Path $work "boot.sh"
        Write-BootScript -Path $boot -RunnerName $runnerName -Token $token
        if ($DryRun) { Write-Host "boot script:"; Get-Content $boot | Write-Host }

        Register-Providers
        $placement = Find-Placement -Id $id -PublicKey $publicKey -Boot $boot -Keep
        if (-not $placement) { throw "No region and size was accepted; nothing was created." }
        $group = $placement.Group

        Write-Host "Creating a $($placement.Size) VM in $($placement.Location) ..."
        $now = (Get-Date).ToUniversalTime()
        Invoke-Tool az (Get-VmArguments $group $placement.Location $placement.Size $publicKey $boot) | Out-Null
        Remove-Item -Force (Join-Path $work "key"), (Join-Path $work "key.pub"), $boot -ErrorAction SilentlyContinue

        # The deadline deletes the group from Azure if this script stops: once the VM powers
        # off after its job (detonation-vm.sh), or after $MaxHours.
        if (-not (Set-Deadline -Group $group -DeleteAfter $now.AddHours($MaxHours))) {
            Write-Warning ("Azure did not accept the deadline (it needs the right to assign " +
                "roles). If this script stops, the VM is billed until " +
                ".\scripts\detonation-vm.ps1 down deletes it.")
            # Then at least Azure's scheduled shutdown, which deallocates the VM. Some
            # regions do not offer it.
            $stop = $now.AddHours($MaxHours).ToString("HHmm")
            Invoke-Tool az @("vm", "auto-shutdown", "--resource-group", $group, "--name",
                "detonation", "--time", $stop, "--output", "none") -AllowFailure | Out-Null
        }

        Wait-Runner -RunnerName $runnerName
        $dispatched = (Get-Date).ToUniversalTime()
        Invoke-Tool gh @("workflow", "run", $Workflow, "--repo", $Repo, "--ref", $Ref,
            "-f", "detonate=all") | Out-Null
        $run = Find-Run -Since $dispatched
        if (-not $run -and -not $DryRun) { throw "The dispatched benchmark run did not appear." }
        if ($run) {
            Write-Host "Benchmark run: $($run.url)"
            Write-Host "If this window closes before it ends, run: .\scripts\detonation-vm.ps1 down"
            # Not captured, so its progress shows as it goes.
            & gh run watch "$($run.databaseId)" --repo $Repo --interval 120 --compact
        }
    }
    finally {
        if ($run -and -not $DryRun) {
            if ((Get-RunStatus -RunId "$($run.databaseId)") -ne "completed") {
                Write-Host "Cancelling the run, which has not finished ..."
                Invoke-Tool gh @("run", "cancel", "$($run.databaseId)", "--repo", $Repo) -AllowFailure | Out-Null
            }
        }
        if ($group) { Remove-Detonation -Groups @($group) }
        Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
        if ($run) { Write-Host "Done. Results: $($run.url)" }
    }
}

switch ($Command) {
    "run" { Start-Detonation }
    "check" { Test-Placement }
    "down" {
        Assert-Tools
        Remove-Detonation -Groups (Get-DetonationGroups)
        Write-Host "No detonation VM or runner is left."
    }
}

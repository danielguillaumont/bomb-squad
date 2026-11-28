"""The disposable detonation VM's scripts agree with the workflow that checks for them.

Nothing here creates a VM: scripts/detonation-vm.ps1 is only parsed, and the boot script is
only read.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from bombsquad.powershell.parser import ParserUnavailable, parse_documents

ROOT = Path(__file__).resolve().parent.parent
BOOT = (ROOT / "scripts" / "detonation-vm.sh").read_text(encoding="utf-8")
DRIVER = (ROOT / "scripts" / "detonation-vm.ps1").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github" / "workflows" / "benchmark.yml").read_text(encoding="utf-8")
DEADLINE = (ROOT / "scripts" / "detonation-deadline.json").read_text(encoding="utf-8")


def test_the_vm_is_marked_and_labelled_as_the_benchmark_job_requires():
    [marker] = set(re.findall(r"/etc/bombsquad/[\w-]+", WORKFLOW))
    assert f"touch {marker}" in BOOT
    [labels] = re.findall(r"fromJSON\('(\[[^']*\])'\)", WORKFLOW)
    wanted = {label.lower() for label in re.findall(r'"([^"]+)"', labels)}
    # The runner's default labels, and the one the boot script adds.
    [added] = re.findall(r"--labels (\S+)", BOOT)
    assert wanted == {"self-hosted", "linux", "x64", *added.lower().split(",")}
    assert "--ephemeral" in BOOT


def test_the_runner_and_powershell_downloads_are_pinned_and_checked():
    for name in ("RUNNER", "PWSH"):
        assert re.search(rf"^{name}_VERSION=\d+\.\d+\.\d+$", BOOT, re.M)
        assert re.search(rf"^{name}_SHA256=[0-9a-f]{{64}}$", BOOT, re.M)
        assert f'echo "${name}_SHA256  ' in BOOT
    assert BOOT.count("sha256sum -c -") == 2
    # The benchmark's static scan parses PowerShell with it.
    assert "/usr/bin/pwsh" in BOOT
    placeholders = {"__REPO_URL__", "__RUNNER_NAME__", "__TOKEN__", "__MAX_MINUTES__"}
    assert set(re.findall(r"__[A-Z_]+__", BOOT)) == placeholders
    assert 'shutdown -h "+$MAX_MINUTES"' in BOOT
    for placeholder in placeholders:
        assert f'Replace("{placeholder}"' in DRIVER


def test_the_vm_has_no_identity_no_inbound_rules_and_only_web_out():
    assert "--assign-identity" not in DRIVER and "Inbound" not in DRIVER
    allowed = re.findall(r'"--access", "Allow".*?"--destination-port-ranges", ([^-]+?)"--output"',
                         DRIVER, re.S)
    assert [re.findall(r'"(\d+)"', ports) for ports in allowed] == [["80", "443"]]
    assert '"--access", "Deny"' in DRIVER
    assert '"auto-shutdown"' in DRIVER and "finally" in DRIVER


def test_the_deadline_can_only_delete_its_own_group_on_a_timer():
    template = json.loads(DEADLINE)
    by_type = {r["type"]: r for r in template["resources"]}
    assert set(by_type) == {"Microsoft.Logic/workflows", "Microsoft.Authorization/roleAssignments"}
    workflow = by_type["Microsoft.Logic/workflows"]
    assert workflow["tags"] == {"bombsquad": "detonation"}
    definition = workflow["properties"]["definition"]
    # Nothing can call it: a timer is its only trigger, with no URL to invoke.
    assert [t["type"] for t in definition["triggers"].values()] == ["Recurrence"]
    # It reads the VM and deletes the group, both by the group's own ID, with its identity.
    uris = workflow["properties"]["parameters"]
    assert all("resourceGroup().id" in v["value"] or "variables('group')" in v["value"]
               for k, v in uris.items() if k.endswith("Uri"))
    assert "resourceGroup().id" in template["variables"]["group"]
    text = json.dumps(definition)
    assert text.count('"method": "DELETE"') == 1 and text.count('"method": "GET"') == 1
    assert "PowerState/stopped" in text and "deleteAfter" in text
    # Its role covers the group it is deployed in, and nothing above: no scope is set.
    role = by_type["Microsoft.Authorization/roleAssignments"]
    assert "scope" not in role and "scope" not in role["properties"]
    assert role["properties"]["principalType"] == "ServicePrincipal"


def test_the_driver_sets_the_deadline_and_the_vm_powers_off_after_its_job():
    assert "detonation-deadline.json" in DRIVER and '"Microsoft.Logic"' in DRIVER
    assert DRIVER.count("Set-Deadline -Group") == 2  # in check, and for the VM
    assert "systemctl is-active --quiet bombsquad-runner" in BOOT
    assert BOOT.index("--unit bombsquad-runner") < BOOT.index("shutdown -h now")


def test_the_driver_parses():
    try:
        _, [document] = parse_documents([("detonation-vm.ps1", DRIVER)])
    except ParserUnavailable:
        pytest.skip("needs PowerShell")
    assert document.parse_errors == []

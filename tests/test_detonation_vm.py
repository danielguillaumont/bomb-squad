"""The disposable detonation VM's scripts agree with the workflow that checks for them.

Nothing here creates a VM: scripts/detonation-vm.ps1 is only parsed, and the boot script is
only read.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from bombsquad.powershell.parser import ParserUnavailable, parse_documents

ROOT = Path(__file__).resolve().parent.parent
BOOT = (ROOT / "scripts" / "detonation-vm.sh").read_text(encoding="utf-8")
DRIVER = (ROOT / "scripts" / "detonation-vm.ps1").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github" / "workflows" / "benchmark.yml").read_text(encoding="utf-8")


def test_the_vm_is_marked_and_labelled_as_the_benchmark_job_requires():
    [marker] = set(re.findall(r"/etc/bombsquad/[\w-]+", WORKFLOW))
    assert f"touch {marker}" in BOOT
    [labels] = re.findall(r"fromJSON\('(\[[^']*\])'\)", WORKFLOW)
    wanted = {label.lower() for label in re.findall(r'"([^"]+)"', labels)}
    # The runner's default labels, and the one the boot script adds.
    [added] = re.findall(r"--labels (\S+)", BOOT)
    assert wanted == {"self-hosted", "linux", "x64", *added.lower().split(",")}
    assert "--ephemeral" in BOOT


def test_the_runner_download_is_pinned_and_checked():
    assert re.search(r"^RUNNER_VERSION=\d+\.\d+\.\d+$", BOOT, re.M)
    assert re.search(r"^RUNNER_SHA256=[0-9a-f]{64}$", BOOT, re.M)
    assert 'sha256sum -c -' in BOOT
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


def test_the_driver_parses():
    try:
        _, [document] = parse_documents([("detonation-vm.ps1", DRIVER)])
    except ParserUnavailable:
        pytest.skip("needs PowerShell")
    assert document.parse_errors == []

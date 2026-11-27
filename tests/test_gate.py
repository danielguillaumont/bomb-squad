"""`bombsquad gate`: lockfile readers, how dependency changes are paired, what a pull request
newly runs, and the comment that reports it.

No test touches the network: dependency versions come from the fake registry used by the
diff tests.
"""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

import pytest

from bombsquad.cli import main
from bombsquad.gate import COMMENT_MARKER, code, gate, plain, render_markdown
from bombsquad.lockfiles import Pins, changes, read_tree, version_key
from bombsquad.model import Level
from tests.test_diff import NOW, STEALER, Registry, manifest, tarball


def write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")
    return root


def npm_lock(packages: dict[str, str], direct: tuple[str, ...] = ()) -> str:
    entries = {"": {"name": "app", "dependencies": {name: "*" for name in direct}}}
    for key, version in packages.items():
        name = key.rsplit("node_modules/", 1)[-1]
        entries[key] = {"version": version,
                        "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"}
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": entries})


# Lockfiles ----------------------------------------------------------------------------------

def test_npm_lockfile(tmp_path):
    lock = json.loads(npm_lock({"node_modules/a": "1.0.0", "node_modules/b/node_modules/a":
                                "0.9.0", "node_modules/@s/c": "2.0.0"}, direct=("a",)))
    lock["packages"]["node_modules/linked"] = {"link": True, "resolved": "packages/linked"}
    lock["packages"]["node_modules/from-git"] = {
        "version": "1.0.0", "resolved": "git+ssh://git@github.com/x/y.git#abc"}
    lock["packages"]["packages/linked"] = {"version": "0.0.1"}
    write(tmp_path, {"package-lock.json": json.dumps(lock)})
    pins = read_tree(tmp_path)
    assert sorted((p.name, p.version, p.direct) for p in pins.pins) == [
        ("@s/c", "2.0.0", False), ("a", "0.9.0", False), ("a", "1.0.0", True)]
    assert "2 entries not from the npm registry" in pins.notes[0]


def test_npm_lockfile_version_1(tmp_path):
    write(tmp_path, {"npm-shrinkwrap.json": json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
        "c": {"version": "github:x/c#abc"}}})})
    pins = read_tree(tmp_path)
    assert sorted((p.name, p.version, p.direct) for p in pins.pins) == [
        ("a", "1.0.0", True), ("b", "2.0.0", False)]
    assert pins.notes


def test_python_lockfiles(tmp_path):
    write(tmp_path, {
        "uv.lock": """
            version = 1
            [[package]]
            name = "app"
            version = "0.1.0"
            source = { editable = "." }
            dependencies = [{ name = "Requests" }]
            [package.dev-dependencies]
            dev = [{ name = "pytest" }]

            [[package]]
            name = "requests"
            version = "2.32.3"
            source = { registry = "https://pypi.org/simple" }

            [[package]]
            name = "pytest"
            version = "8.4.0"
            source = { registry = "https://pypi.org/simple" }

            [[package]]
            name = "urllib3"
            version = "2.2.0"
            source = { registry = "https://pypi.org/simple" }

            [[package]]
            name = "private"
            version = "1.0"
            source = { git = "https://example.invalid/private.git" }
            """,
        "sub/poetry.lock": """
            [[package]]
            name = "Typing_Extensions"
            version = "4.12.0"

            [[package]]
            name = "internal"
            version = "1.0"
            [package.source]
            type = "legacy"
            url = "https://pypi.example.invalid/simple"
            """,
        "requirements-dev.txt": """
            # pinned
            black==24.8.0 \\
                --hash=sha256:00
            Flask[async]==3.0.3 ; python_version >= "3.9"
            idna>=3
            -r other.txt
            -e .
            """,
        "yarn.lock": "",
    })
    pins = read_tree(tmp_path)
    found = sorted((p.lockfile, p.name, p.version, p.direct) for p in pins.pins)
    assert found == [
        ("requirements-dev.txt", "black", "24.8.0", True),
        ("requirements-dev.txt", "flask", "3.0.3", True),
        ("sub/poetry.lock", "typing-extensions", "4.12.0", False),
        ("uv.lock", "pytest", "8.4.0", True),
        ("uv.lock", "requests", "2.32.3", True),
        ("uv.lock", "urllib3", "2.2.0", False)]
    assert any("yarn.lock" in n and "not read" in n for n in pins.notes)
    assert any("sub/poetry.lock" in n for n in pins.notes)
    assert any("uv.lock: 1 packages" in n for n in pins.notes)


def test_broken_lockfile_is_a_note(tmp_path):
    write(tmp_path, {"package-lock.json": "{", "uv.lock": "[[package"})
    pins = read_tree(tmp_path)
    assert pins.pins == [] and len(pins.notes) == 2


def test_changes_pair_each_new_version_with_the_one_it_replaces(tmp_path):
    base = write(tmp_path / "base", {"package-lock.json": npm_lock(
        {"node_modules/a": "1.0.0", "node_modules/x/node_modules/a": "2.0.0",
         "node_modules/b": "1.2.0"})})
    head = write(tmp_path / "head", {"package-lock.json": npm_lock(
        {"node_modules/a": "1.0.1", "node_modules/x/node_modules/a": "2.0.0",
         "node_modules/b": "1.10.0", "node_modules/new": "0.1.0"}, direct=("b",))})
    found = changes(read_tree(base), read_tree(head))
    assert [(c.name, c.old, c.new, c.direct) for c in found] == [
        ("b", "1.2.0", "1.10.0", True), ("a", "1.0.0", "1.0.1", False),
        ("new", None, "0.1.0", False)]
    assert found[0].spec == "npm:b@1.2.0..1.10.0"
    assert version_key("1.10.0") > version_key("1.9.0")
    assert changes(Pins(), Pins()) == []


# The gate -----------------------------------------------------------------------------------

WORKFLOW = """
    on: issues
    permissions: {}
    jobs:
      greet:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{ github.event.issue.title }}"
    """


def project(tmp_path: Path, demo: str | None, extra: dict[str, str] | None = None,
            name: str = "base") -> Path:
    packages = {"node_modules/demo": demo} if demo else {}
    return write(tmp_path / name, {"package.json": manifest(), "package-lock.json": npm_lock(
        packages, direct=("demo",)), **(extra or {})})


def registry_with_demo() -> Registry:
    registry = Registry()
    registry.npm("demo", {
        "1.0.0": {"tarball": tarball({"package.json": manifest()}),
                  "time": "2026-10-01T00:00:00Z"},
        "1.0.1": {"tarball": tarball({"package.json": manifest({"postinstall": "node s.js"}),
                                      "s.js": STEALER}), "time": "2026-11-26T00:00:00Z"}})
    return registry


def test_pull_request_that_adds_a_workflow_and_bumps_a_dependency(tmp_path):
    base = project(tmp_path, "1.0.0")
    head = project(tmp_path, "1.0.1", {".github/workflows/greet.yml": WORKFLOW}, name="head")
    report = gate(base, head, registry_with_demo(), NOW)
    assert [e.path for e in report.repository.added_entries] == [".github/workflows/greet.yml"]
    assert "BS-GHA-002" in {f.rule.id for f in report.repository.added_findings}
    [review] = report.dependencies
    assert review.change.spec == "npm:demo@1.0.0..1.0.1" and review.error is None
    assert [e.kind for e in review.report.added_entries] == ["postinstall script"]
    assert "recent-release" in {s.id for s in review.report.signals}
    assert report.highest_level() is Level.HIGH
    data = report.to_dict()
    assert data["kind"] == "gate" and data["dependencies"][0]["diff"]["subject"] == "npm:demo"


def test_new_dependency_is_reviewed_on_its_own(tmp_path):
    base = project(tmp_path, None)
    head = project(tmp_path, "1.0.1", name="head")
    report = gate(base, head, registry_with_demo(), NOW)
    [review] = report.dependencies
    assert review.change.old is None
    assert [e.kind for e in review.report.added_entries] == ["postinstall script"]
    assert {s.id for s in review.report.signals} == {"recent-release"}


def test_limit_and_registry_errors(tmp_path):
    base = project(tmp_path, "1.0.0")
    head = write(tmp_path / "head", {"package.json": manifest(), "package-lock.json": npm_lock(
        {"node_modules/demo": "1.0.1", "node_modules/missing": "1.0.0",
         "node_modules/zzz": "1.0.0"}, direct=("demo",))})
    report = gate(base, head, registry_with_demo(), NOW, max_packages=2)
    assert [d.change.name for d in report.dependencies] == ["demo", "missing"]
    assert "HTTP 404" in report.dependencies[1].error
    assert [c.name for c in report.not_reviewed] == ["zzz"]
    text = render_markdown(report)
    assert "could not be reviewed" in text and "over the limit" in text


def test_nothing_new(tmp_path):
    base = project(tmp_path, "1.0.0")
    head = project(tmp_path, "1.0.0", name="head")
    (head / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")  # a worktree
    report = gate(base, head, registry_with_demo(), NOW)
    assert report.highest_level() is None and report.dependencies == []
    assert report.repository.added_files == []
    text = render_markdown(report)
    assert text.startswith(COMMENT_MARKER)
    assert "Nothing new reported" in text and "No new findings does not mean safe." in text


def test_folders_must_be_separate(tmp_path):
    base = project(tmp_path, None)
    with pytest.raises(ValueError):
        gate(base, base)
    (base / "inner").mkdir()
    with pytest.raises(ValueError):
        gate(base / "inner", base)


# The comment --------------------------------------------------------------------------------

def test_text_from_the_pull_request_cannot_format_the_comment_or_mention_anyone():
    assert plain("@octocat see [x](https://e.invalid) <img src=x>") == (
        "&#64;octocat see \\[x\\]\\(https://e.invalid\\) \\<img src=x\\>")
    assert code("a ``b`` c") == "```a ``b`` c```"
    assert code("`x") == "`` `x ``"
    assert code("line one\nline two") == "`line one line two`"
    assert code("x" * 500).endswith("…`")


def test_comment_escapes_paths_and_stays_under_the_limit(tmp_path):
    base = project(tmp_path, None)
    files = {f".github/workflows/w{i}.yml": WORKFLOW for i in range(40)}
    files[".github/workflows/@here`x.yml"] = WORKFLOW
    head = project(tmp_path, None, files, name="head")
    report = gate(base, head, registry_with_demo(), NOW)
    text = render_markdown(report)
    # Mentions inside code spans do not notify; the backtick cannot end the span early.
    assert "``.github/workflows/@here`x.yml:5``" in text
    assert "@here" not in re.sub(r"(`+).*?\1", "", text)  # nowhere outside code
    assert "… and" in text  # more entry points than the comment lists
    assert len(text) < 65_536


# Command line -------------------------------------------------------------------------------

def test_cli_gate_writes_every_format(tmp_path, capsys):
    base = project(tmp_path, None)
    head = project(tmp_path, None, {".github/workflows/greet.yml": WORKFLOW}, name="head")
    out = tmp_path / "out"
    out.mkdir()
    status = main(["gate", str(base), str(head), "--markdown", str(out / "gate.md"),
                   "--json", str(out / "gate.json"), "--sarif", str(out / "gate.sarif"),
                   "--fail-on", "high"])
    assert status == 1
    assert "Repository: base -> head" in capsys.readouterr().out
    assert (out / "gate.md").read_text(encoding="utf-8").startswith(COMMENT_MARKER)
    assert json.loads((out / "gate.json").read_text(encoding="utf-8"))["highest_level"] == "high"
    sarif = json.loads((out / "gate.sarif").read_text(encoding="utf-8"))
    assert {r["ruleId"] for r in sarif["runs"][0]["results"]} >= {"BS-GHA-002"}
    assert main(["gate", str(base), str(base)]) == 2

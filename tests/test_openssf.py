"""OpenSSF malicious-packages lookups for the benchmark. Report files are made up here."""

from __future__ import annotations

import json
from pathlib import Path

from benchmark import openssf, score


def report(report_id, ecosystem, name, versions=(), ranges=(), **extra) -> dict:
    return {"id": report_id, **extra, "affected": [{
        "package": {"ecosystem": ecosystem, "name": name},
        "versions": list(versions), "ranges": list(ranges)}]}


def write(root: Path, ecosystem: str, name: str, data: dict) -> None:
    folder = root / openssf.folder(ecosystem, name)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{data['id']}.json").write_text(json.dumps(data), encoding="utf-8")


def test_names_are_written_as_the_reports_write_them():
    assert openssf.registry_name("npm", "@scope@pkg") == "@scope/pkg"
    assert openssf.registry_name("npm", "plain") == "plain"
    assert openssf.registry_name("pypi", "Some_Pkg.Name") == "some-pkg-name"
    assert openssf.folder("npm", "@scope@pkg") == "osv/malicious/npm/@scope/pkg"


def test_only_the_sampled_names_report_files_are_fetched():
    listing = [
        "osv/malicious/npm/keyv/MAL-2026-11524.json",
        "osv/malicious/npm/keyv-other/MAL-2026-1.json",
        "osv/malicious/npm/@scope/pkg/MAL-2025-7.json",
        "osv/malicious/pypi/some-pkg/MAL-2024-3.json",
        "osv/malicious/npm/keyv/README.md",
        "osv/malicious/npm/keyv/../../x/MAL-2026-2.json",
    ]
    wanted = [("npm", "keyv"), ("npm", "@scope@pkg"), ("pypi", "Some_Pkg")]
    assert openssf.paths(listing, wanted) == [
        "osv/malicious/npm/@scope/pkg/MAL-2025-7.json",
        "osv/malicious/npm/keyv/MAL-2026-11524.json",
        "osv/malicious/pypi/some-pkg/MAL-2024-3.json",
    ]


def test_how_a_report_covers_a_version():
    listed = report("MAL-1", "npm", "pkg", versions=["1.0.0"])
    every = report("MAL-2", "npm", "pkg", ranges=[{"type": "SEMVER",
                                                     "events": [{"introduced": "0"}]}])
    bounded = report("MAL-3", "npm", "pkg", ranges=[{"type": "SEMVER", "events": [
        {"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}])
    assert openssf.covers(listed, "npm", "pkg", "1.0.0") == "version"
    assert openssf.covers(listed, "npm", "pkg", "2.0.0") == "name"
    assert openssf.covers(every, "npm", "pkg", "9.9.9") == "all versions"
    assert openssf.covers(bounded, "npm", "pkg", "1.1.0") == "name"  # ranges not evaluated
    onward = report("MAL-5", "npm", "pkg", ranges=[{"type": "SEMVER",
                                                      "events": [{"introduced": "9.0.0"}]}])
    assert openssf.covers(onward, "npm", "pkg", "9.0.0") == "version"
    assert openssf.covers(onward, "npm", "pkg", "9.1.0") == "name"
    assert openssf.covers(listed, "pypi", "pkg", "1.0.0") is None  # another ecosystem
    assert openssf.covers({**listed, "withdrawn": "2026-01-01T00:00:00Z"}, "npm", "pkg",
                          "1.0.0") is None
    assert openssf.covers(report("MAL-4", "PyPI", "Some_Pkg", versions=["2.0"]),
                          "pypi", "some-pkg", "2.0") == "version"


def test_lookup_takes_the_best_cover_and_lists_every_report(tmp_path):
    write(tmp_path, "npm", "@scope@pkg", report("MAL-2025-7", "npm", "@scope/pkg",
                                                versions=["0.1.0"]))
    write(tmp_path, "npm", "@scope@pkg", report("MAL-2026-9", "npm", "@scope/pkg",
                                                versions=["1.0.0"]))
    found = openssf.lookup(tmp_path, "npm", "@scope@pkg", "1.0.0")
    assert found == {"reports": ["MAL-2025-7", "MAL-2026-9"], "covers": "version"}
    assert openssf.lookup(tmp_path, "npm", "missing", "1.0.0") == {"reports": [],
                                                                   "covers": None}


def test_lookup_never_leaves_the_checkout(tmp_path):
    outside = tmp_path / "osv" / "x"
    outside.mkdir(parents=True)
    (outside / "MAL-2026-1.json").write_text(json.dumps(
        report("MAL-2026-1", "npm", "..", versions=["1"])), encoding="utf-8")
    for name in ("../x", "..", "a/../../x"):
        assert openssf.lookup(tmp_path / "osv" / "malicious", "npm", name, "1")["covers"] \
            is None


def test_recall_on_the_samples_a_report_confirms():
    meta = {"openssf": {"repo": openssf.REPO, "commit": openssf.COMMIT,
                        "date": openssf.COMMIT_DATE}}

    def row(covers, levels, ecosystem="npm"):
        return {"set": "malicious", "ecosystem": ecosystem, "splits": ["retrospective"],
                "bombsquad": {"levels": levels}, "guarddog": {"issues": 0, "label": "low"},
                "openssf": {"reports": ["MAL-1"] if covers else [], "covers": covers}}

    rows = [row("version", ["high"]), row("all versions", []), row("name", ["high"]),
            row(None, ["review"]), row("version", ["review"], "pypi")]
    scores = score.score(meta, rows)
    npm = next(e for e in scores["openssf"] if e["ecosystem"] == "npm")
    assert npm["covered"] == {"version": 1, "all versions": 1, "name only": 1, "no report": 1}
    review = next(r for r in npm["results"] if r["tool"] == "bombsquad"
                  and r["threshold"] == "review")
    assert (review["recall"]["count"], review["recall"]["of"]) == (1, 2)
    text = score.markdown(scores)
    assert "OpenSSF malicious-packages report confirms" in text
    assert openssf.COMMIT[:12] in text


def test_runs_without_openssf_have_no_section():
    assert "openssf" not in score.score({}, [])

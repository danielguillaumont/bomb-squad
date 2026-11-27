"""The benchmark harness: selecting samples, opening the dataset's encrypted archives,
benign lists and releases, reading each tool's output, and scoring.

Nothing here is malware. Encrypted samples are built in memory from harmless files with
the traditional PKWARE cipher the dataset uses, so the decryption path is tested without
a real sample.
"""

from __future__ import annotations

import io
import json
import random
import struct
import zlib
from datetime import UTC, date, datetime

import pytest

from benchmark import benign, samples, score, tools
from benchmark.__main__ import main as bench_main
from bombsquad.archive import ArchiveError, unpack
from tests.test_diff import Registry, manifest, tarball


def _crc_byte(crc: int, byte: int) -> int:
    return zlib.crc32(bytes([byte]), crc ^ 0xFFFFFFFF) ^ 0xFFFFFFFF


class _Cipher:
    def __init__(self, password: bytes) -> None:
        self.keys = [0x12345678, 0x23456789, 0x34567890]
        for byte in password:
            self.update(byte)

    def update(self, byte: int) -> None:
        k0, k1, k2 = self.keys
        k0 = _crc_byte(k0, byte)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = _crc_byte(k2, (k1 >> 24) & 0xFF)
        self.keys = [k0, k1, k2]

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for byte in data:
            temp = (self.keys[2] | 2) & 0xFFFF
            out.append(byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
            self.update(byte)
        return bytes(out)


def encrypted_zip(files: dict[str, bytes], password: bytes = b"infected") -> bytes:
    """A ZIP with stored members encrypted with ZipCrypto, as `zip -P` writes."""
    body, central = io.BytesIO(), io.BytesIO()
    rng = random.Random(1)
    for name, data in files.items():
        crc = zlib.crc32(data)
        header = bytes(rng.randrange(256) for _ in range(11)) + bytes([crc >> 24])
        payload = _Cipher(password).encrypt(header + data)
        offset = body.tell()
        raw = name.encode()
        body.write(struct.pack("<4s2B4HL2L2H", b"PK\x03\x04", 20, 0, 1, 0, 0, 0x21, crc,
                               len(payload), len(data), len(raw), 0) + raw + payload)
        central.write(struct.pack("<4s4B4HL2L5H2L", b"PK\x01\x02", 20, 3, 20, 0, 1, 0, 0,
                                  0x21, crc, len(payload), len(data), len(raw), 0, 0, 0, 0,
                                  0o100644 << 16, offset) + raw)
    directory = central.getvalue()
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, len(files), len(files),
                      len(directory), body.tell(), 0)
    return body.getvalue() + directory + end


LISTING = [
    "samples/npm/malicious_intent/evil-a/1.0.0/2024-01-02-evil-a-v1.0.0.zip",
    "samples/npm/malicious_intent/evil-a/1.0.1/2024-01-03-evil-a-v1.0.1.zip",
    "samples/npm/compromised_lib/@scope/lib/2.0.0/2026-12-01-lib-v2.0.0.zip",
    "samples/pypi/malicious_intent/badpy/0.1/2025-05-05-badpy-v0.1.zip",
    "samples/pypi/manifest.json",
    "samples/ide_extensions/x/1/2024-01-01-x-v1.zip",
    "README.md",
]


def test_listing_and_selection():
    parsed = samples.parse_listing(LISTING)
    assert [(s.ecosystem, s.kind, s.name, s.version, s.discovered) for s in parsed] == [
        ("npm", "malicious_intent", "evil-a", "1.0.0", "2024-01-02"),
        ("npm", "malicious_intent", "evil-a", "1.0.1", "2024-01-03"),
        ("npm", "compromised_lib", "@scope/lib", "2.0.0", "2026-12-01"),
        ("pypi", "malicious_intent", "badpy", "0.1", "2025-05-05")]
    chosen = samples.select(parsed, 10, 7, date(2026, 11, 27))
    assert len([s for s in chosen if s.name == "evil-a"]) == 1  # one version per package
    by_name = {s.name: s.splits for s in chosen}
    assert by_name["@scope/lib"] == ("after-cutoff", "retrospective")
    assert by_name["badpy"] == ("retrospective",)
    assert samples.select(parsed, 10, 7, date(2026, 11, 27)) == chosen  # seeded


def test_encrypted_sample_is_opened_and_its_package_found(tmp_path):
    inner = tarball({"package.json": manifest(), "index.js": "1;\n"})
    data = encrypted_zip({"2024-01-02-evil-a-v1.0.0/evil-a-1.0.0.tgz": inner})
    path = "samples/npm/malicious_intent/evil-a/1.0.0/2024-01-02-evil-a-v1.0.0.zip"
    (tmp_path / "dataset" / path).parent.mkdir(parents=True)
    (tmp_path / "dataset" / path).write_bytes(data)
    [sample] = samples.parse_listing([path])
    root, notes = samples.extract(sample, tmp_path / "dataset", tmp_path / "work")
    assert (root / "package.json").is_file() and notes == []
    with pytest.raises(ArchiveError):
        unpack(data, "x.zip", tmp_path / "wrong", b"wrong password")
    with pytest.raises(ArchiveError):
        unpack(data, "x.zip", tmp_path / "none")


def test_python_package_root(tmp_path):
    (tmp_path / "a" / "badpy-0.1").mkdir(parents=True)
    (tmp_path / "a" / "badpy-0.1" / "setup.py").write_text("", encoding="utf-8")
    (tmp_path / "a" / "badpy-0.1" / "tests").mkdir()
    (tmp_path / "a" / "badpy-0.1" / "tests" / "setup.py").write_text("", encoding="utf-8")
    assert samples.package_root("pypi", tmp_path) == tmp_path / "a" / "badpy-0.1"
    assert samples.package_root("npm", tmp_path) == tmp_path


def test_benign_lists():
    text = "export const topDownload = [\n  'semver',\n  '@types/node',\n  'semver'\n]\n"
    assert benign.npm_names_from(text) == ["semver", "@types/node"]
    rows = json.dumps({"last_update": "2026-11-01", "rows": [
        {"project": "boto3", "download_count": 3}, {"project": "urllib3"}, {"x": 1}]})
    assert benign.pypi_names_from(rows) == ["boto3", "urllib3"]
    names = [f"p{i}" for i in range(50)]
    picked = benign.sample_names(names, 20, 5, 1, "npm")
    assert len(picked) == 5 and set(picked) <= set(names[:20])
    assert benign.sample_names(names, 20, 5, 1, "npm") == picked


def test_release_current_on_a_date():
    registry = Registry()
    registry.urls["https://registry.npmjs.org/demo"] = json.dumps({
        "versions": {"1.0.0": {}, "1.1.0": {}, "0.9.9": {}, "2.0.0-beta.1": {}, "2.0.0": {}},
        "time": {"1.0.0": "2026-01-01T00:00:00Z", "1.1.0": "2026-06-01T00:00:00Z",
                 "0.9.9": "2026-08-01T00:00:00Z",  # a backport, published later
                 "2.0.0-beta.1": "2026-07-01T00:00:00Z",
                 "2.0.0": "2026-12-01T00:00:00Z"}}).encode()
    registry.urls["https://pypi.org/pypi/demo/json"] = json.dumps({"releases": {
        "1.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z"}],
        "1.1": [{"upload_time_iso_8601": "2026-02-01T00:00:00Z", "yanked": True}],
        "1.2rc1": [{"upload_time_iso_8601": "2026-03-01T00:00:00Z"}],
        "1.0.post1": [{"upload_time_iso_8601": "2026-03-02T00:00:00Z"}]}}).encode()
    as_of = datetime(2026, 11, 5, tzinfo=UTC)
    assert benign.release_on("npm", "demo", as_of, registry) == "1.1.0"
    assert benign.release_on("pypi", "demo", as_of, registry) == "1.0.post1"
    registry.urls["https://pypi.org/pypi/beta/json"] = json.dumps({"releases": {
        "0.58b0": [{"upload_time_iso_8601": "2026-09-01T00:00:00Z"}],
        "0.59b0": [{"upload_time_iso_8601": "2026-10-01T00:00:00Z"}],
        "0.60b0": [{"upload_time_iso_8601": "2026-12-01T00:00:00Z"}]}}).encode()
    assert benign.release_on("pypi", "beta", as_of, registry) == "0.59b0"


def test_tool_output_is_reduced_to_what_scoring_needs():
    bs = tools.parse_bombsquad(json.dumps({
        "findings": [{"rule_id": "BS-EX-001", "level": "high", "evidence": "secret stuff"},
                     {"rule_id": "BS-NET-001", "level": "review"}],
        "entry_points": [{"surface": "npm"}], "files": [{"status": "analysed"},
                                                         {"status": "not_analysed"}]}))
    assert bs == {"levels": ["high", "review"], "rules": ["BS-EX-001", "BS-NET-001"],
                  "rules_by_level": {"high": ["BS-EX-001"], "review": ["BS-NET-001"]},
                  "surfaces": ["npm"], "not_analysed": 1}
    assert "secret stuff" not in json.dumps(bs)
    gd = tools.parse_guarddog("log line\n" + json.dumps({
        "issues": 2, "results": {"npm-install-script": {"x": 1}, "shady-links": {}},
        "errors": {"some-rule": "failed"},
        "risk_score": {"score": 5.4, "label": "suspicious", "findings_count": 3},
        "risks": [{"threat_code": "secret stuff"}]}))
    assert gd == {"issues": 2, "rules": ["npm-install-script"], "rule_errors": ["some-rule"],
                  "score": 5.4, "label": "suspicious"}
    assert "secret stuff" not in json.dumps(gd)
    assert tools.parse_guarddog(json.dumps({"issues": 0}))["label"] is None
    with pytest.raises(ValueError):
        tools.parse_guarddog("no json")


def row(set_: str, eco: str, bs_levels: list[str] | None, gd_issues: int | None,
        surfaces: list[str] | None = None, splits=("retrospective",)) -> dict:
    return {"set": set_, "ecosystem": eco, "name": "x", "splits": list(splits),
            "bombsquad": ({"levels": bs_levels, "surfaces": surfaces or []}
                          if bs_levels is not None else {"error": "timed out"}),
            "guarddog": ({"issues": gd_issues,
                          "label": {0: "no_risks_detected", 1: "low"}.get(gd_issues,
                                                                          "suspicious")}
                         if gd_issues is not None else {"error": "exit 2"})}


def test_scores_keep_their_denominators(tmp_path):
    rows = [row("malicious", "npm", ["high"], 1, ["npm"]),
            row("malicious", "npm", ["review"], 0, ["npm"]),
            row("malicious", "npm", [], 1),
            row("malicious", "npm", None, 1),
            row("benign", "npm", ["review"], 0),
            row("benign", "npm", [], 1),
            row("benign", "npm", [], 0),
            {"set": "benign", "ecosystem": "npm", "name": "gone", "prepare_error": "x: y"}]
    scores = score.score({"dataset_commit": "abc"}, rows)
    get = {(r["ecosystem"], r["split"], r["tool"], r["threshold"]): r
           for r in scores["results"]}
    high = get[("npm", "retrospective", "bombsquad", "high")]
    assert high["recall"] == {"count": 1, "of": 3, "rate": 0.3333}
    assert high["errors"] == {"malicious": 1, "benign": 0}
    assert high["false_positives"]["count"] == 0 and high["false_positives"]["of"] == 3
    review = get[("npm", "retrospective", "bombsquad", "review")]
    assert review["recall"]["count"] == 2 and review["false_positives_per_1000"] == 333.3
    assert review["precision"] == {"count": 2, "of": 3, "rate": 0.6667}
    gd = get[("npm", "retrospective", "guarddog", "any")]
    assert gd["recall"] == {"count": 3, "of": 4, "rate": 0.75}
    assert get[("npm", "after-cutoff", "guarddog", "any")]["recall"]["of"] == 0
    assert get[("npm", "retrospective", "guarddog", "suspicious")]["recall"]["count"] == 0
    flagged_row = row("benign", "npm", [], 2)
    assert score.flagged(flagged_row, "guarddog", "suspicious") is True
    assert score.flagged(flagged_row, "guarddog", "high_risk") is False
    assert score.flagged({"guarddog": {"issues": 1}}, "guarddog", "suspicious") is None
    assert scores["packages"] == {"total": 8, "unusable": 1, "unusable_reasons": ["x"]}
    surfaces = {(s["surface"], s["tool"], s["threshold"]): s["recall"]
                for s in scores["surfaces"]}
    assert surfaces[("npm", "bombsquad", "high")]["of"] == 2
    assert surfaces[("(no entry point found)", "guarddog", "any")]["count"] == 1
    text = score.markdown(scores)
    assert "33.3% (1/3)" in text and "n/a (0)" in text
    assert "No findings does not mean safe." in text and "favours it" in text


def test_benchmark_cli_select_and_score(tmp_path, capsys):
    listing = tmp_path / "listing.txt"
    listing.write_text("\n".join(LISTING) + "\n", encoding="utf-8")
    out = tmp_path / "selected.json"
    assert bench_main(["select", "--listing", str(listing), "--per-ecosystem", "5",
                       "--cutoff", "2026-11-27", "-o", str(out), "--paths",
                       str(tmp_path / "paths.txt")]) == 0
    assert len(json.loads(out.read_text(encoding="utf-8"))["samples"]) == 3
    assert len((tmp_path / "paths.txt").read_text(encoding="utf-8").splitlines()) == 3
    results = tmp_path / "results.jsonl"
    results.write_text(json.dumps({"meta": {"seed": 1}}) + "\n" + json.dumps(
        row("malicious", "pypi", ["high"], 0)) + "\n", encoding="utf-8")
    assert bench_main(["score", str(results), "--json", str(tmp_path / "s.json")]) == 0
    assert "| pypi | Bomb Squad, a high finding | 100.0% (1/1)" in capsys.readouterr().out

"""The command line, the v1 sample, and the JSON and SARIF outputs."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from bombsquad.cli import main
from bombsquad.sources import decode

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "samples" / "example.ps1"
V1_RULES = ["BS-FS-001", "BS-SS-001", "BS-RG-001", "BS-ID-001", "BS-TS-001", "BS-DE-001"]


@pytest.fixture(scope="module")
def sample_reports(tmp_path_factory):
    out = tmp_path_factory.mktemp("reports")
    for fmt in ("json", "sarif"):
        assert main(["scan", str(SAMPLE), "--format", fmt, "--output", str(out / fmt)]) == 0
    return {fmt: json.loads((out / fmt).read_text(encoding="utf-8")) for fmt in ("json", "sarif")}


def test_v1_sample_still_produces_its_six_findings(sample_reports):
    findings = sample_reports["json"]["findings"]
    assert [f["rule_id"] for f in findings] == V1_RULES
    assert [f["line"] for f in findings] == [6, 7, 8, 9, 10, 11]


def test_json_states_limits_and_parser(sample_reports):
    report = sample_reports["json"]
    assert "No findings does not mean safe." in report["limitations"]
    assert report["parser"]["name"] == "PowerShell"
    assert report["files"][0]["status"] == "analysed"


def test_sarif_shape(sample_reports):
    sarif = sample_reports["sarif"]
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len({r["id"] for r in rules}) == len(rules)
    assert run["columnKind"] == "utf16CodeUnits"
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"].endswith("samples/example.ps1")
        assert location["region"]["startLine"] >= 1 and location["region"]["startColumn"] >= 1
        assert result["level"] in ("error", "warning", "note")
        assert len(result["partialFingerprints"]["bombsquad/v1"]) == 32


def test_fail_on(tmp_path):
    out = str(tmp_path / "r.txt")
    assert main(["scan", str(SAMPLE), "--fail-on", "high", "-o", out]) == 1
    assert main(["scan", str(SAMPLE), "--fail-on", "never", "-o", out]) == 0


def test_stdin(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"rm C:\\x\n")))
    assert main(["scan", "-", "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert [f["rule_id"] for f in report["findings"]] == ["BS-FS-001"]
    assert report["findings"][0]["path"] == "<stdin>"


def test_missing_path_is_an_error(capsys):
    assert main(["scan", "does-not-exist.ps1"]) == 2
    assert "not found" in capsys.readouterr().err


def test_malformed_assembly_qualified_type_names_do_not_stop_the_scan(tmp_path, capsys):
    # On .NET (pwsh), reading TypeName.FullName parses the assembly part and throws on
    # some malformed names; two malicious npm samples stopped whole scans this way.
    odd = ["[Foo, a/b]", '[Foo, "x"]', "[Foo, a=b=c]", "[Foo, a,b=]", "[Foo, ,]",
           "[Foo, Version=1.2.3.4.5]", "[Foo, Culture=zz-qq-ww]", "[Foo, a b c]"]
    (tmp_path / "odd.ps1").write_text("".join(f"$x = {t}::Bar()\n" for t in odd),
                                      encoding="utf-8")
    (tmp_path / "ok.ps1").write_text("Remove-Item C:\\x\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert {f["rule_id"] for f in report["findings"] if f["path"].endswith("ok.ps1")} == {
        "BS-FS-001"}


def test_decode_keeps_bytes_meaning():
    assert decode("Get-Date\r\n".encode("utf-16"))[0] == "Get-Date\r\n"
    assert decode(b"\xef\xbb\xbfls")[1] == "utf-8-sig"
    assert decode(b"caf\xe9")[1] == "cp1252"
    # A UTF-16 BOM on bytes that are not UTF-16 (seen in a test file of a popular
    # package) is read with replacement characters instead of stopping the scan.
    text, encoding = decode(b"\xff\xfea\x00b\x00\n")
    assert encoding == "utf-16" and text.startswith("ab")


def test_json_on_standard_output_is_ascii_and_files_are_utf8(tmp_path, capsys, monkeypatch):
    # Piped on Windows, standard output is encoded in the console's code page, which cannot
    # hold every character: JSON written there must survive any code page.
    text = "x = 'caf" + chr(0xE9) + " " + chr(0x1F3F4) + "'; eval(x" + chr(0x200B) + ")\n"
    (tmp_path / "setup.py").write_text(text, encoding="utf-8")
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    for fmt in ("json", "sarif"):
        assert main(["scan", str(tmp_path), "--format", fmt]) == 0
        sys.stdout.flush()
        data = raw.getvalue()
        raw.seek(0)
        raw.truncate()
        assert data.isascii()
        assert chr(0x1F3F4) in json.dumps(json.loads(data.decode("ascii")), ensure_ascii=False)
    monkeypatch.undo()
    out = tmp_path / "report.json"
    assert main(["scan", str(tmp_path), "--format", "json", "-o", str(out)]) == 0
    assert chr(0xE9) in out.read_text(encoding="utf-8")

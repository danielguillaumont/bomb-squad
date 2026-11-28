"""The flag log, the defusal record and the site built from them.

Nothing here touches the network. Package names, versions, notes and evidence are treated
as attacker-controlled: the site must escape them, and build links only from values that
pass the registry's rules or from https links a person recorded.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta

import pytest

from watch import ledger, review, site
from watch.__main__ import main as watch_main

T0 = datetime(2026, 11, 28, 6, 0, tzinfo=UTC)
BASE = "https://example.github.io/watch/"


def queued(name="demo", version="1.1.1", previous="1.1.0", status="queued for review"):
    return {"ecosystem": "npm", "name": name, "version": version, "previous": previous,
            "published": "2026-11-27T08:00:00+00:00", "status": status,
            "reasons": ["1 new or changed entry points that installing runs (npm)"]}


def diff_of(name="demo", old="1.1.0", new="1.1.1", runs="node setup.js", evidence="fetch(u)"):
    return {"kind": "diff", "subject": f"npm:{name}", "old": {"version": old},
            "new": {"version": new}, "limitations": ["Static analysis only."],
            "entry_points": {"added": [{"surface": "npm", "kind": "postinstall script",
                                        "trigger": "install", "path": "package.json",
                                        "line": 5, "runs": runs}], "changed": []},
            "findings": {"added": [
                {"rule_id": "BS-NET-003", "level": "review", "title": "Opens network connections",
                 "path": "setup.js", "line": 2, "evidence": evidence, "effect": "Sends data."},
                {"rule_id": "BS-PRC-001", "level": "info", "title": "Starts other programs",
                 "path": "setup.js", "line": 3, "evidence": "spawn()", "effect": "x"}]},
            "signals": [{"signal": "recent-release", "level": "review", "detail": "1 day"},
                        {"signal": "publisher-changed", "level": "review", "detail": "a -> b"}]}


# The ledger ---------------------------------------------------------------------------------

def test_entries_chain_and_any_change_breaks_the_chain(tmp_path):
    log = tmp_path / "flags.jsonl"
    for i in range(3):
        ledger.append(log, {"kind": "note", "n": i}, T0 + timedelta(minutes=i))
    entries = ledger.verify(log)
    assert [e["seq"] for e in entries] == [1, 2, 3]
    assert entries[0]["prev"] == ledger.GENESIS and entries[1]["prev"] == entries[0]["hash"]
    lines = log.read_text(encoding="utf-8").splitlines()

    def broken(text, message):
        log.write_text(text, encoding="utf-8")
        with pytest.raises(ledger.LedgerError, match=message):
            ledger.verify(log)

    broken("\n".join([lines[0], lines[1].replace('"n": 1', '"n": 9'), lines[2]]) + "\n",
           "hash does not match")
    broken("\n".join([lines[0], lines[2]]) + "\n", "where 2 was expected")  # dropped
    broken("\n".join([lines[1], lines[0], lines[2]]) + "\n", "where 1 was expected")
    rewritten = json.loads(lines[1])
    rewritten["n"] = 9
    rewritten["hash"] = ledger.digest(rewritten)  # recomputed: the next entry still breaks
    broken("\n".join([lines[0], json.dumps(rewritten), lines[2]]) + "\n",
           "does not follow")
    broken("\n".join(lines) + "\nnot json\n", "not JSON")


def test_a_kept_head_shows_a_rewritten_history(tmp_path):
    log = tmp_path / "flags.jsonl"
    first = ledger.append(log, {"kind": "note", "n": 1}, T0)
    ledger.check_head(ledger.verify(log), 1, first["hash"])
    # Someone rewrites the whole file consistently: the chain verifies, the kept head does not.
    log.unlink()
    ledger.append(log, {"kind": "note", "n": 2}, T0)
    with pytest.raises(ledger.LedgerError, match="has changed"):
        ledger.check_head(ledger.verify(log), 1, first["hash"])
    with pytest.raises(ledger.LedgerError, match="no longer in the file"):
        ledger.check_head(ledger.verify(log), 5, first["hash"])


def test_the_ledger_sets_its_own_fields_and_keeps_time_in_order(tmp_path):
    log = tmp_path / "flags.jsonl"
    with pytest.raises(ledger.LedgerError, match="sets seq"):
        ledger.append(log, {"seq": 7})
    ledger.append(log, {"kind": "note"}, T0)
    with pytest.raises(ledger.LedgerError, match="clock is behind"):
        ledger.append(log, {"kind": "note"}, T0 - timedelta(seconds=1))
    assert len(ledger.verify(log)) == 1


# Reviews and reports --------------------------------------------------------------------------

def test_only_a_queued_release_can_be_reviewed(tmp_path):
    queue = tmp_path / "results.jsonl"
    queue.write_text(json.dumps({"meta": {}}) + "\n" + json.dumps(queued()) + "\n"
                     + json.dumps(queued("quiet", status="nothing new found")) + "\n",
                     encoding="utf-8")
    assert review.queued_row(queue, "npm", "demo", "1.1.1")["previous"] == "1.1.0"
    with pytest.raises(review.ReviewError, match="was not queued"):
        review.queued_row(queue, "npm", "quiet", "1.1.1")
    with pytest.raises(review.ReviewError, match="is not in"):
        review.queued_row(queue, "npm", "other", "1.0.0")
    for bad in ("npm:demo", "npm:<b>@1", "gem:demo@1", "npm:demo@1 2", "pypi:-x@1"):
        with pytest.raises(review.ReviewError):
            review.parse_release(bad)
    assert review.parse_release("npm:@scope/name@1.0.0") == ("npm", "@scope/name", "1.0.0")


def test_a_listed_release_keeps_the_evidence_of_the_diff_that_was_read():
    with pytest.raises(review.ReviewError, match="needs the diff"):
        review.flag_record(queued(), None, "listed", "Gained a hook.", "dg")
    with pytest.raises(review.ReviewError, match="not of npm:demo@1.1.0..1.1.1"):
        review.flag_record(queued(), diff_of(new="1.2.0"), "listed", "x", "dg")
    with pytest.raises(review.ReviewError, match="note"):
        review.flag_record(queued(), diff_of(), "listed", "  ", "dg")
    record = review.flag_record(queued(), diff_of(evidence="x" * 1000), "listed",
                                "Gained a postinstall that fetches.", "dg")
    evidence = record["evidence"]
    assert [f["rule_id"] for f in evidence["findings"]] == ["BS-NET-003"]  # not info
    assert [s["signal"] for s in evidence["signals"]] == ["publisher-changed"]  # not age
    assert len(evidence["findings"][0]["evidence"]) == review.EVIDENCE_CHARS
    assert "evidence" not in review.flag_record(queued(), None, "not listed",
                                                "A build step.", "dg")


def test_reports_need_a_listed_release_and_confirmations_need_a_link(tmp_path):
    flags, defusals = tmp_path / "flags.jsonl", tmp_path / "defusals.jsonl"
    ledger.append(flags, review.flag_record(queued(), diff_of(), "listed", "Hook.", "dg"), T0)
    ledger.append(flags, review.flag_record(queued("b"), None, "not listed", "Fine.", "dg"), T0)
    entries = ledger.verify(flags)
    with pytest.raises(review.ReviewError, match="not a release a review listed"):
        review.report_record(entries, 2, "npm", "https://example.invalid/r/1")
    with pytest.raises(review.ReviewError, match="https link"):
        review.report_record(entries, 1, "npm", "javascript:alert(1)")
    ledger.append(defusals, review.report_record(entries, 1, "openssf",
                                                 "https://github.com/ossf/x/pull/1"), T0)
    record = ledger.verify(defusals)
    with pytest.raises(review.ReviewError, match="needs the https link"):
        review.outcome_record(record, 1, "confirmed", None)
    with pytest.raises(review.ReviewError, match="not a report"):
        review.outcome_record(record, 2, "declined", None)
    # A later review takes a release off the list; reports on it can no longer be added.
    ledger.append(flags, review.flag_record(queued(), None, "not listed", "Explained.", "dg"),
                  T0 + timedelta(hours=1))
    with pytest.raises(review.ReviewError):
        review.report_record(ledger.verify(flags), 1, "npm", "https://example.invalid/r/2")


# The site -------------------------------------------------------------------------------------

def _ledgers(tmp_path, note="Gained a postinstall that fetches.", runs="node setup.js",
             outcome=None):
    flags, defusals = tmp_path / "flags.jsonl", tmp_path / "defusals.jsonl"
    ledger.append(flags, review.flag_record(queued(), diff_of(runs=runs), "listed", note,
                                            "dg"), T0)
    ledger.append(flags, review.flag_record(queued("hidden", "2.0.0", "1.0.0"), None,
                                            "not listed", "Fine.", "dg"), T0)
    if outcome:
        ledger.append(defusals, review.report_record(ledger.verify(flags), 1, "npm",
                                                     "https://example.invalid/report/1"), T0)
        ledger.append(defusals, review.outcome_record(ledger.verify(defusals), 1, outcome,
                                                      "https://example.invalid/advisory"), T0)
    return flags, defusals


def test_the_site_lists_only_reviewed_and_listed_updates(tmp_path):
    flags, defusals = _ledgers(tmp_path)
    built = site.build(flags, defusals, tmp_path / "out", BASE, T0)
    assert built["listed"] == 1 and built["flags_head"][0] == 2
    page = (tmp_path / "out" / "index.html").read_text(encoding="utf-8")
    assert "npm:demo@1.1.1" in page and "hidden" not in page
    assert 'href="https://www.npmjs.com/package/demo/v/1.1.1"' in page
    assert "bombsquad diff npm:demo@1.1.0..1.1.1" in page
    assert "not a verdict" in page and "does not mean safe" in page
    assert "malicious" not in page
    assert "<script" not in page and "Content-Security-Policy" in page
    root = ET.fromstring((tmp_path / "out" / "feed.xml").read_bytes())
    entries = root.findall("{http://www.w3.org/2005/Atom}entry")
    assert len(entries) == 1 and entries[0].find(
        "{http://www.w3.org/2005/Atom}id").text == BASE + "index.html#flag-1"
    assert (tmp_path / "out" / "flags.jsonl").read_bytes() == flags.read_bytes()


def test_package_text_is_escaped_everywhere(tmp_path):
    hostile = '"><script>alert(1)</script><a href="javascript:x">'
    flags, defusals = _ledgers(tmp_path, note=hostile, runs=hostile)
    site.build(flags, defusals, tmp_path / "out", BASE, T0)
    page = (tmp_path / "out" / "index.html").read_text(encoding="utf-8")
    assert "<script" not in page and 'href="javascript' not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    feed = (tmp_path / "out" / "feed.xml").read_bytes()
    ET.fromstring(feed)  # still well-formed
    assert b"<script" not in feed
    assert site.registry_url("npm:<x>@1") is None
    assert site.link("javascript:alert(1)", "x") == "x"


def test_only_a_confirmed_outcome_with_its_link_says_malicious(tmp_path):
    for outcome, says in (("removed", False), ("confirmed", True)):
        work = tmp_path / outcome
        flags, defusals = _ledgers(work, outcome=outcome)
        site.build(flags, defusals, work / "out", BASE, T0)
        page = (work / "out" / "index.html").read_text(encoding="utf-8")
        record = (work / "out" / "defusals.html").read_text(encoding="utf-8")
        assert ("confirmed malicious" in page) is says
        assert ('href="https://example.invalid/advisory"' in record)
        assert "Reported to npm" in record


def test_the_site_is_not_built_from_a_broken_ledger(tmp_path):
    flags, defusals = _ledgers(tmp_path)
    flags.write_text(flags.read_text(encoding="utf-8").replace("Gained", "Lost"),
                     encoding="utf-8")
    with pytest.raises(ledger.LedgerError):
        site.build(flags, defusals, tmp_path / "out", BASE, T0)
    with pytest.raises(ValueError, match="base URL"):
        site.build(defusals, defusals, tmp_path / "out", "http://example.invalid/", T0)


def test_the_commands_record_reviews_reports_and_check_heads(tmp_path, capsys):
    queue = tmp_path / "results.jsonl"
    queue.write_text(json.dumps(queued()) + "\n", encoding="utf-8")
    diff = tmp_path / "diff.json"
    diff.write_text(json.dumps(diff_of()), encoding="utf-8")
    flags, defusals = tmp_path / "flags.jsonl", tmp_path / "defusals.jsonl"
    assert watch_main(["review", "npm:demo@1.1.1", "--queue", str(queue), "--diff", str(diff),
                       "--outcome", "listed", "--note", "Hook.", "--reviewer", "dg",
                       "--log", str(flags)]) == 0
    assert watch_main(["report", "--flags", str(flags), "--flag", "1", "--to", "npm",
                       "--reference", "https://example.invalid/r", "--record",
                       str(defusals)]) == 0
    assert watch_main(["outcome", "--record", str(defusals), "--report", "1", "--outcome",
                       "no response"]) == 0
    head = ledger.verify(flags)[0]["hash"]
    capsys.readouterr()
    assert watch_main(["verify", str(flags), "--head", f"1:{head}"]) == 0
    assert f"head 1:{head}" in capsys.readouterr().out
    assert watch_main(["verify", str(flags), "--head", "1:" + "0" * 64]) == 2
    assert watch_main(["review", "npm:demo@1.1.1", "--queue", str(queue), "--outcome",
                       "listed", "--note", "x", "--reviewer", "dg", "--log", str(flags)]) == 2
    assert watch_main(["site", "--flags", str(flags), "--defusals", str(defusals), "--out",
                       str(tmp_path / "out"), "--base-url", BASE]) == 0

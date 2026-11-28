"""What a human review adds to the flag log, and what a report adds to the defusal record.

The daily watch only queues releases. Nothing reaches the flag log, and so the site and the
feed, except through `review`, which records a person's decision. A report can be recorded
only against a release a person listed, and a release is called confirmed malicious only
when a report's outcome says so with a link to the confirmation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from watch.daily import AGE_SIGNALS

NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$", re.I)
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_!-]{0,63}$")
LINK = re.compile(r"^https://[^\s<>\"'`]+$")
OUTCOMES = ("listed", "not listed")
REPORTED_TO = ("npm", "pypi", "openssf")
# Confirmed: the registry, OpenSSF malicious-packages or the maintainer confirmed that the
# release is malicious. The only outcome that lets the site call it so, and only with a link.
REPORT_OUTCOMES = ("confirmed", "removed", "declined", "no response")
EVIDENCE_CHARS = 300  # of each entry point's command and each finding's evidence
MAX_ITEMS = 50
MAX_NOTE = 2000


class ReviewError(Exception):
    """The review or report cannot be recorded as given."""


def parse_release(spec: str) -> tuple[str, str, str]:
    """`npm:name@version` or `pypi:name@version`, checked, as (ecosystem, name, version)."""
    ecosystem, _, rest = spec.partition(":")
    name, at, version = rest.rpartition("@")
    pattern = {"npm": NPM_NAME, "pypi": PYPI_NAME}.get(ecosystem)
    if not (pattern and at and pattern.match(name) and VERSION.match(version)):
        raise ReviewError(f"not an npm: or pypi: name@version: {spec!r}")
    return ecosystem, name, version


def release_id(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}@{version}"


def _clip(text: object, limit: int = EVIDENCE_CHARS) -> str:
    text = "" if text is None else str(text)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def queued_row(queue: Path, ecosystem: str, name: str, version: str) -> dict:
    """The release's row in a daily run's results, which must have queued it."""
    for line in queue.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if (row.get("ecosystem"), row.get("name"), row.get("version")) == (ecosystem, name,
                                                                         version):
            if row.get("status") != "queued for review":
                raise ReviewError(f"{release_id(ecosystem, name, version)} was not queued "
                                  f"for review: {row.get('status')}")
            return row
    raise ReviewError(f"{release_id(ecosystem, name, version)} is not in {queue.name}")


def evidence(diff: dict, ecosystem: str, name: str, old: str, new: str) -> dict:
    """From `bombsquad diff --format json` on this update, what the site shows: the entry
    points it gained or changed, its new findings at review or high, and its publish signals
    at review or high. Each command and piece of evidence is cut to a few hundred
    characters, and nothing else from the diff is kept."""
    if diff.get("kind") != "diff" or diff.get("subject") != f"{ecosystem}:{name}" or \
            (diff.get("old") or {}).get("version") != old or \
            (diff.get("new") or {}).get("version") != new:
        raise ReviewError(f"the diff is not of {ecosystem}:{name}@{old}..{new}")
    entries = diff.get("entry_points") or {}
    gained = [*(entries.get("added") or []),
              *[c.get("new") or {} for c in entries.get("changed") or []]]
    findings = [f for f in (diff.get("findings") or {}).get("added") or []
                if f.get("level") in ("review", "high")]
    signals = [s for s in diff.get("signals") or []
               if s.get("level") in ("review", "high") and s.get("signal") not in AGE_SIGNALS]
    return {
        "entry_points": [{"surface": _clip(e.get("surface"), 40), "kind": _clip(e.get("kind"), 80),
                          "trigger": _clip(e.get("trigger"), 80),
                          "path": _clip(e.get("path"), 200), "line": e.get("line"),
                          "runs": _clip(e.get("runs"))} for e in gained[:MAX_ITEMS]],
        "findings": [{"rule_id": _clip(f.get("rule_id"), 20), "level": f.get("level"),
                      "title": _clip(f.get("title"), 120), "path": _clip(f.get("path"), 200),
                      "line": f.get("line"), "evidence": _clip(f.get("evidence")),
                      "effect": _clip(f.get("effect"))} for f in findings[:MAX_ITEMS]],
        "signals": [{"signal": _clip(s.get("signal"), 60), "level": s.get("level"),
                     "detail": _clip(s.get("detail"))} for s in signals[:MAX_ITEMS]],
        "limitations": [_clip(text) for text in diff.get("limitations") or []],
    }


def flag_record(row: dict, diff: dict | None, outcome: str, note: str, reviewer: str) -> dict:
    """The flag log entry for one reviewed release. A listed release needs the diff the
    reviewer read, so the site can show its evidence."""
    if outcome not in OUTCOMES:
        raise ReviewError(f"the outcome is one of {', '.join(OUTCOMES)}")
    note, reviewer = note.strip(), reviewer.strip()
    if not note or len(note) > MAX_NOTE:
        raise ReviewError(f"say in a note, of at most {MAX_NOTE} characters, what the review "
                          "found")
    if not reviewer:
        raise ReviewError("name the reviewer")
    record = {"kind": "review", "release": release_id(row["ecosystem"], row["name"],
                                                      row["version"]),
              "compared_with": row.get("previous"), "published": row.get("published"),
              "reasons": list(row.get("reasons") or []), "outcome": outcome, "note": note,
              "reviewer": reviewer}
    if outcome == "listed":
        if diff is None:
            raise ReviewError("a listed release needs the diff the review read (--diff)")
        record["evidence"] = evidence(diff, row["ecosystem"], row["name"], row["previous"],
                                      row["version"])
    return record


def listed(flags: list[dict]) -> dict[int, dict]:
    """The flag log's listed releases by sequence number. A later review of the same
    release supersedes an earlier one, so a release can be taken off the list."""
    latest: dict[str, dict] = {}
    for entry in flags:
        if entry.get("kind") == "review":
            latest[entry["release"]] = entry
    return {e["seq"]: e for e in latest.values() if e.get("outcome") == "listed"}


def report_record(flags: list[dict], flag: int, reported_to: str, reference: str) -> dict:
    """A defusal record entry for a report sent about a listed release."""
    entry = listed(flags).get(flag)
    if entry is None:
        raise ReviewError(f"flag log entry {flag} is not a release a review listed")
    if reported_to not in REPORTED_TO:
        raise ReviewError(f"reported to one of {', '.join(REPORTED_TO)}")
    if not LINK.match(reference):
        raise ReviewError("the reference is the report's https link")
    return {"kind": "report", "release": entry["release"], "flag": flag,
            "reported_to": reported_to, "reference": reference}


def outcome_record(defusals: list[dict], report: int, outcome: str, link: str | None,
                   note: str = "") -> dict:
    """A later entry that records what became of a report. Earlier entries stay as they are."""
    reports = {e["seq"]: e for e in defusals if e.get("kind") == "report"}
    if report not in reports:
        raise ReviewError(f"defusal record entry {report} is not a report")
    if outcome not in REPORT_OUTCOMES:
        raise ReviewError(f"the outcome is one of {', '.join(REPORT_OUTCOMES)}")
    if outcome in ("confirmed", "removed") and not (link and LINK.match(link)):
        raise ReviewError(f"a {outcome} outcome needs the https link that shows it")
    if link and not LINK.match(link):
        raise ReviewError("the link must be https")
    record = {"kind": "outcome", "report": report, "release": reports[report]["release"],
              "outcome": outcome, "note": _clip(note.strip(), MAX_NOTE)}
    if link:
        record["link"] = link
    return record


def report_states(defusals: list[dict]) -> list[dict]:
    """Each report with its outcomes so far, oldest report first."""
    reports = {e["seq"]: {**e, "outcomes": []} for e in defusals if e.get("kind") == "report"}
    for e in defusals:
        if e.get("kind") == "outcome" and e.get("report") in reports:
            reports[e["report"]]["outcomes"].append(e)
    return list(reports.values())


__all__ = ["OUTCOMES", "REPORT_OUTCOMES", "ReviewError", "evidence", "flag_record", "listed",
           "outcome_record", "parse_release", "queued_row", "report_record", "report_states"]

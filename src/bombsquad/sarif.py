"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from bombsquad.model import Finding, Level, ScanReport
from bombsquad.powershell.rules import RULES

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/danielguillaumont/bomb-squad"
LEVELS = {Level.HIGH: "error", Level.REVIEW: "warning", Level.INFO: "note"}


def _uri(path: str) -> str:
    if path.startswith("<"):
        return path.strip("<>")
    if re.match(r"^[A-Za-z]:/|^/", path):
        return Path(path).as_uri()
    return path


def _fingerprint(f: Finding) -> str:
    evidence = " ".join(f.evidence.split())
    return hashlib.sha256(f"{f.rule.id}|{f.path}|{evidence}".encode()).hexdigest()[:32]


def _message(f: Finding) -> str:
    parts = [f"{f.rule.title}. {f.rule.effect}"]
    if f.via:
        parts.append("How it was found: " + "; ".join(f.via) + ".")
    limitations = [*f.rule.limitations, *f.limitations]
    if limitations:
        parts.append("Limits: " + " ".join(limitations))
    parts.append(f.rule.next_step)
    return " ".join(parts)


def to_sarif(report: ScanReport) -> dict:
    rules = sorted(RULES.values(), key=lambda r: r.id)
    index = {r.id: i for i, r in enumerate(rules)}
    results = []
    for f in report.findings:
        results.append({
            "ruleId": f.rule.id,
            "ruleIndex": index[f.rule.id],
            "level": LEVELS[f.level],
            "message": {"text": _message(f)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(f.path), "uriBaseId": "%SRCROOT%"}
                    if not _uri(f.path).startswith("file:")
                    else {"uri": _uri(f.path)},
                    "region": {
                        "startLine": f.region.line,
                        "startColumn": f.region.column,
                        "endLine": f.region.end_line,
                        "endColumn": f.region.end_column,
                        "snippet": {"text": f.evidence},
                    },
                }
            }],
            "partialFingerprints": {"bombsquad/v1": _fingerprint(f)},
            "properties": {"family": f.rule.family, "bombsquadLevel": f.level.value},
        })
    notifications = [
        {"level": "note", "message": {"text": f"{r.path}: {note}"}}
        for r in report.files for note in r.notes
    ]
    run = {
        "tool": {
            "driver": {
                "name": "Bomb Squad",
                "version": report.tool_version,
                "informationUri": INFORMATION_URI,
                "rules": [
                    {
                        "id": r.id,
                        "name": "".join(w.capitalize() for w in re.findall(r"[A-Za-z0-9]+",
                                                                            r.title)),
                        "shortDescription": {"text": r.title},
                        "fullDescription": {"text": r.effect},
                        "help": {"text": r.next_step},
                        "defaultConfiguration": {"level": LEVELS[r.level]},
                        "properties": {"tags": ["security", r.family]},
                    }
                    for r in rules
                ],
            }
        },
        "columnKind": "utf16CodeUnits",
        "results": results,
        "invocations": [{"executionSuccessful": True,
                         "toolExecutionNotifications": notifications}],
    }
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}

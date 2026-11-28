"""Run each tool on one unpacked package, in its own process with a time limit, and keep
only what scoring needs: whether it flagged the package, which rules, how long it took.

Neither tool runs the package: Bomb Squad parses it, and GuardDog matches Semgrep and YARA
rules against it. GuardDog is given the folder, so its local scan runs its source-code
rules; its registry-metadata rules need package metadata and do not run.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from bombsquad.scan import runs_on_install

TIMEOUT_SECONDS = 300
LEVELS = ("high", "review", "info")


def _run(command: list[str], timeout: int) -> tuple[str | None, str | None, float]:
    start = time.monotonic()
    try:
        done = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return None, f"timed out after {timeout} s", time.monotonic() - start
    except OSError as exc:
        return None, f"could not start: {exc}", time.monotonic() - start
    elapsed = time.monotonic() - start
    # Exit 1 means "found something" to both tools, but it is also what Python exits with
    # on an uncaught exception, so output without a JSON object is an error too.
    if done.returncode not in (0, 1) or "{" not in done.stdout:
        tail = done.stderr.strip().splitlines()[-1:] or [f"exit {done.returncode}"]
        return done.stdout, f"exit {done.returncode}: {tail[0][:300]}", elapsed
    return done.stdout, None, elapsed


def _json_object(text: str) -> dict:
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in the output")
    value = json.loads(text[start:])
    if not isinstance(value, dict):
        raise ValueError("unexpected JSON")
    return value


def parse_bombsquad(text: str) -> dict:
    data = _json_object(text)
    levels = {f.get("level") for f in data.get("findings", [])}
    return {
        "levels": [level for level in LEVELS if level in levels],
        "rules": sorted({f.get("rule_id") for f in data.get("findings", [])
                         if isinstance(f.get("rule_id"), str)}),
        "rules_by_level": {level: sorted({f.get("rule_id") for f in data.get("findings", [])
                                          if f.get("level") == level
                                          and isinstance(f.get("rule_id"), str)})
                           for level in LEVELS if level in levels},
        "surfaces": sorted({e.get("surface") for e in data.get("entry_points", [])
                            if isinstance(e.get("surface"), str)}),
        "not_analysed": sum(1 for f in data.get("files", [])
                            if f.get("status") != "analysed"),
    }


def parse_guarddog(text: str) -> dict:
    data = _json_object(text)
    results = data.get("results") if isinstance(data.get("results"), dict) else {}
    issues = data.get("issues")
    errors = data.get("errors") if isinstance(data.get("errors"), dict) else {}
    # GuardDog 3 correlates rule matches into a 0-10 risk score labelled low, suspicious
    # or high_risk. Its exit code still counts any matched rule.
    risk = data.get("risk_score") if isinstance(data.get("risk_score"), dict) else {}
    score, label = risk.get("score"), risk.get("label")
    return {
        "issues": issues if isinstance(issues, int) else 0,
        "rules": sorted(name for name, found in results.items() if found),
        "rule_errors": sorted(errors),
        "score": score if isinstance(score, int | float) else None,
        "label": label if isinstance(label, str) else None,
    }


def bombsquad(root: Path, timeout: int = TIMEOUT_SECONDS,
              findings: list | None = None) -> dict:
    """The reduced result. When `findings` is a list, the report's full findings are added
    to it for triage; they are never part of the result."""
    out, error, seconds = _run([sys.executable, "-m", "bombsquad", "scan", str(root),
                                "--package", "--format", "json"], timeout)
    result: dict = {"seconds": round(seconds, 2), "error": error}
    if error is None:
        try:
            result.update(parse_bombsquad(out))
            if findings is not None:
                findings.extend(_json_object(out).get("findings") or [])
        except ValueError as exc:
            result["error"] = f"unreadable output: {exc}"
    return result


def parse_diff(text: str) -> dict:
    """What an update newly gains, reduced to kinds, rule IDs and signal names."""
    data = _json_object(text)
    entries = data.get("entry_points") if isinstance(data.get("entry_points"), dict) else {}
    added = [e for e in entries.get("added", []) if isinstance(e, dict)]
    changed = [c.get("new") for c in entries.get("changed", [])
               if isinstance(c, dict) and isinstance(c.get("new"), dict)]
    installed = [e for e in added + changed if runs_on_install(
        str(e.get("surface")), str(e.get("kind")), str(e.get("trigger")))]
    findings = (data.get("findings") or {}).get("added", [])
    findings = [f for f in findings if isinstance(f, dict)]
    levels = {f.get("level") for f in findings}
    return {
        "entry_points": {"added": len(added), "changed": len(changed),
                         "surfaces": sorted({e.get("surface") for e in added + changed
                                             if isinstance(e.get("surface"), str)}),
                         # The ones installing the package runs, as `scan --package` judges.
                         "run_on_install": len(installed),
                         "install_surfaces": sorted({e.get("surface") for e in installed
                                                     if isinstance(e.get("surface"), str)})},
        "levels": [level for level in LEVELS if level in levels],
        "rules_by_level": {level: sorted({f.get("rule_id") for f in findings
                                          if f.get("level") == level
                                          and isinstance(f.get("rule_id"), str)})
                           for level in LEVELS if level in levels},
        "signals": sorted({f"{s.get('signal')}:{s.get('level')}"
                           for s in data.get("signals", []) if isinstance(s, dict)}),
        "grew": len((data.get("files") or {}).get("grew", [])),
    }


def bombsquad_diff(ecosystem: str, name: str, old: str, new: str,
                   timeout: int = TIMEOUT_SECONDS) -> dict:
    """`bombsquad diff` on an update, as the pull-request gate reviews one: both releases
    fetched from the registry, checked against its hashes, and scanned, never run."""
    out, error, seconds = _run([sys.executable, "-m", "bombsquad", "diff",
                                f"{ecosystem}:{name}@{old}..{new}", "--format", "json"],
                               timeout)
    result: dict = {"seconds": round(seconds, 2), "error": error}
    if error is None:
        try:
            result.update(parse_diff(out))
        except ValueError as exc:
            result["error"] = f"unreadable output: {exc}"
    return result


def guarddog(executable: str, ecosystem: str, root: Path,
             timeout: int = TIMEOUT_SECONDS) -> dict:
    out, error, seconds = _run([executable, ecosystem, "scan", str(root),
                                "--output-format", "json"], timeout)
    result: dict = {"seconds": round(seconds, 2), "error": error}
    if error is None:
        try:
            result.update(parse_guarddog(out))
        except ValueError as exc:
            result["error"] = f"unreadable output: {exc}"
    return result


def version(executable: str) -> str | None:
    return version_of([executable, "--version"])


def version_of(command: list[str]) -> str | None:
    """The last line the command prints. Not through `_run`, which expects a JSON report
    and would count plain text as an error."""
    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = done.stdout.strip().splitlines()
    return lines[-1].strip() if done.returncode == 0 and lines else None

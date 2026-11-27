"""Scores from a results file: recall on malicious samples, false positives on benign
releases, and precision on this mixture, per ecosystem, split and surface, always with the
counts they come from."""

from __future__ import annotations

import json
import statistics
from pathlib import Path

DETECTORS = (
    ("bombsquad", "high", "Bomb Squad, a high finding"),
    ("bombsquad", "review", "Bomb Squad, a review or high finding"),
    ("guarddog", "high_risk", "GuardDog, high risk"),
    ("guarddog", "suspicious", "GuardDog, suspicious or high risk"),
    ("guarddog", "any", "GuardDog, any rule (its exit code)"),
)
# Scored only in runs that detonated: what package code was seen doing in the sandbox.
DETONATION_DETECTORS = (
    ("detonation", "flagged", "Detonation, a fake credential read or sent, or persistence"),
    ("detonation", "any", "Detonation, anything observed"),
    ("combined", "review", "Bomb Squad review or high, or detonation flagged"),
)
# Updates of benign packages, each diffed against the release before it: how often the
# diff, and so the pull-request gate, raises something on an ordinary update. Release age
# is left out, because it is measured from when the benchmark runs, not from the update.
DIFF_DETECTORS = (
    ("findings", "Diff: a new review or high finding"),
    ("high", "Diff: a new high finding"),
    ("entry_points", "Diff: a new or changed entry point"),
    ("any", "Diff: a new review or high finding, or a publish signal at review"),
)
AGE_SIGNALS = ("recent-release", "release-age")
GUARDDOG_LABELS = {"high_risk": {"high_risk"}, "suspicious": {"suspicious", "high_risk"}}
SPLITS = ("retrospective", "after-cutoff")


def load(path: Path) -> tuple[dict, list[dict]]:
    meta: dict = {}
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if "meta" in record:
            meta = record["meta"]
        else:
            rows.append(record)
    return meta, rows


def detonated(row: dict) -> bool:
    return isinstance(row.get("detonation"), dict)


def flagged(row: dict, tool: str, threshold: str) -> bool | None:
    """True or False, or None when the tool failed on this package."""
    if tool == "combined":
        static, dynamic = flagged(row, "bombsquad", threshold), flagged(row, "detonation",
                                                                        "flagged")
        if static or dynamic:
            return True
        return None if static is None or dynamic is None else False
    result = row.get(tool) or {}
    if result.get("error"):
        return None
    if tool == "detonation":
        return bool(result.get("flagged") if threshold == "flagged" else result.get("seen"))
    if tool == "guarddog":
        if threshold == "any":
            return result.get("issues", 0) > 0
        if result.get("label") is None:
            return None  # no risk score in the output
        return result["label"] in GUARDDOG_LABELS[threshold]
    if "levels" not in result:
        return None  # no result was read
    levels = set(result["levels"])
    return "high" in levels if threshold == "high" else bool(levels & {"high", "review"})


def diff_alarm(result: dict, threshold: str) -> bool:
    levels = set(result.get("levels") or [])
    if threshold == "high":
        return "high" in levels
    findings = bool(levels & {"high", "review"})
    if threshold == "findings":
        return findings
    entries = result.get("entry_points") or {}
    if threshold == "entry_points":
        return bool(entries.get("added") or entries.get("changed"))
    signals = [s.rsplit(":", 1) for s in result.get("signals") or []]
    return findings or any(level in ("review", "high") and name not in AGE_SIGNALS
                           for name, level in signals)


def _updates(rows: list[dict]) -> list[dict]:
    """False alarms on benign updates, per ecosystem, with the rules behind them."""
    out = []
    for ecosystem in ("npm", "pypi"):
        benign = [r for r in rows if r["set"] == "benign" and r["ecosystem"] == ecosystem
                  and "previous" in r]
        diffed = [r["diff"] for r in benign if isinstance(r.get("diff"), dict)]
        ok = [d for d in diffed if not d.get("error")]
        rules: dict[str, int] = {}
        for d in ok:
            for rule in {*d.get("rules_by_level", {}).get("high", []),
                         *d.get("rules_by_level", {}).get("review", [])}:
                rules[rule] = rules.get(rule, 0) + 1
        seconds = [d["seconds"] for d in ok if isinstance(d.get("seconds"), int | float)]
        out.append({
            "ecosystem": ecosystem, "releases": len(benign),
            "no_earlier_release": sum(1 for r in benign if not r.get("previous")),
            "errors": len(diffed) - len(ok),
            "alarms": [{"threshold": t, "label": label,
                        **_rate(sum(1 for d in ok if diff_alarm(d, t)), len(ok))}
                       for t, label in DIFF_DETECTORS],
            "rules": sorted(rules.items(), key=lambda kv: (-kv[1], kv[0])),
            "median_seconds": round(statistics.median(seconds), 1) if seconds else None,
        })
    return out


def _rate(numerator: int, denominator: int) -> dict:
    return {"count": numerator, "of": denominator,
            "rate": round(numerator / denominator, 4) if denominator else None}


def _confusion(malicious: list[dict], benign: list[dict], tool: str, threshold: str) -> dict:
    if tool in ("detonation", "combined"):  # only the packages this run detonated
        malicious = [r for r in malicious if detonated(r)]
        benign = [r for r in benign if detonated(r)]
    hits = [flagged(r, tool, threshold) for r in malicious]
    alarms = [flagged(r, tool, threshold) for r in benign]
    tp, fn = hits.count(True), hits.count(False)
    fp, tn = alarms.count(True), alarms.count(False)
    return {
        "recall": _rate(tp, tp + fn),
        "false_positives": _rate(fp, fp + tn),
        "false_positives_per_1000": round(1000 * fp / (fp + tn), 1) if fp + tn else None,
        "precision": _rate(tp, tp + fp),
        "errors": {"malicious": hits.count(None), "benign": alarms.count(None)},
    }


def detectors(meta: dict) -> tuple:
    return DETECTORS + (DETONATION_DETECTORS if meta.get("detonate", "none") != "none" else ())


def _cost(rows: list[dict]) -> dict:
    done = [r["detonation"] for r in rows if detonated(r)]
    seconds = [d["seconds"] for d in done if isinstance(d.get("seconds"), int | float)]
    return {"packages": len(done), "errors": sum(1 for d in done if d.get("error")),
            "timed_out": sum(1 for d in done if d.get("timed_out")),
            "median_seconds": round(statistics.median(seconds), 1) if seconds else None,
            "total_seconds": round(sum(seconds), 1)}


def score(meta: dict, rows: list[dict]) -> dict:
    usable = [r for r in rows if not r.get("prepare_error")]
    out: dict = {"meta": meta, "packages": {
        "total": len(rows), "unusable": len(rows) - len(usable),
        "unusable_reasons": sorted({r["prepare_error"].split(":")[0] for r in rows
                                    if r.get("prepare_error")})[:20]},
        "results": []}
    for ecosystem in ("npm", "pypi"):
        benign = [r for r in usable if r["set"] == "benign" and r["ecosystem"] == ecosystem]
        for split in SPLITS:
            malicious = [r for r in usable if r["set"] == "malicious"
                         and r["ecosystem"] == ecosystem and split in r.get("splits", [])]
            for tool, threshold, label in detectors(meta):
                out["results"].append({"ecosystem": ecosystem, "split": split, "tool": tool,
                                       "threshold": threshold, "label": label,
                                       **_confusion(malicious, benign, tool, threshold)})
        # Per surface: the malicious packages in which Bomb Squad found that kind of
        # entry point, and those where it found none.
        malicious = [r for r in usable if r["set"] == "malicious" and r["ecosystem"] == ecosystem
                     and "retrospective" in r.get("splits", [])]
        groups: dict[str, list[dict]] = {}
        for r in malicious:
            if (r.get("bombsquad") or {}).get("error"):
                continue  # its entry points are not known
            surfaces = (r.get("bombsquad") or {}).get("surfaces") or ["(no entry point found)"]
            for surface in surfaces:
                groups.setdefault(surface, []).append(r)
        for surface, members in sorted(groups.items()):
            for tool, threshold, label in detectors(meta):
                scored = ([r for r in members if detonated(r)]
                          if tool in ("detonation", "combined") else members)
                hits = [flagged(r, tool, threshold) for r in scored]
                out.setdefault("surfaces", []).append({
                    "ecosystem": ecosystem, "surface": surface, "tool": tool,
                    "threshold": threshold, "label": label,
                    "recall": _rate(hits.count(True), hits.count(True) + hits.count(False))})
    if meta.get("version_pairs"):
        out["updates"] = _updates(usable)
    if meta.get("detonate", "none") != "none":
        out["detonation_cost"] = [
            {"ecosystem": e, "set": kind,
             **_cost([r for r in usable if r["ecosystem"] == e and r["set"] == kind])}
            for e in ("npm", "pypi") for kind in ("malicious", "benign")]
    return out


def _cell(rate: dict) -> str:
    if not rate["of"]:
        return "n/a (0)"
    # From the counts: formatting the stored, already rounded rate rounds twice, and
    # 100/185 (54.05...%) would show as 54.0%.
    return f"{100 * rate['count'] / rate['of']:.1f}% ({rate['count']}/{rate['of']})"


def markdown(scores: dict) -> str:
    meta = scores["meta"]
    lines = ["## Benchmark: Bomb Squad and GuardDog on the same packages", ""]
    lines += [f"- {key}: {value}" for key, value in meta.items()]
    p = scores["packages"]
    lines += [f"- packages: {p['total']}, of which {p['unusable']} could not be prepared "
              "and are left out", ""]
    for split in SPLITS:
        lines += [f"### {split}", "",
                  "| Ecosystem | Detector | Recall | False positives | Per 1,000 benign | "
                  "Precision on this mix | Errors (malicious, benign) |",
                  "|---|---|---|---|---|---|---|"]
        for r in scores["results"]:
            if r["split"] != split:
                continue
            per = r["false_positives_per_1000"]
            lines.append(f"| {r['ecosystem']} | {r['label']} | {_cell(r['recall'])} | "
                         f"{_cell(r['false_positives'])} | "
                         f"{'n/a' if per is None else per} | {_cell(r['precision'])} | "
                         f"{r['errors']['malicious']}, {r['errors']['benign']} |")
        lines.append("")
    lines += ["### Recall by the entry point Bomb Squad found (retrospective)", "",
              "| Ecosystem | Surface | Detector | Recall |", "|---|---|---|---|"]
    for r in scores.get("surfaces", []):
        lines.append(f"| {r['ecosystem']} | {r['surface']} | {r['label']} | "
                     f"{_cell(r['recall'])} |")
    if scores.get("updates"):
        lines += ["", "### Updates of benign packages (diff against the release before)", "",
                  "| Ecosystem | Detector | False alarms | Per 1,000 updates |",
                  "|---|---|---|---|"]
        for u in scores["updates"]:
            for a in u["alarms"]:
                per = "n/a" if not a["of"] else round(1000 * a["count"] / a["of"], 1)
                lines.append(f"| {u['ecosystem']} | {a['label']} | {_cell(a)} | {per} |")
        lines.append("")
        for u in scores["updates"]:
            rules = ", ".join(f"{rule} ({n})" for rule, n in u["rules"][:10]) or "none"
            median = "n/a" if u["median_seconds"] is None else u["median_seconds"]
            lines.append(f"- {u['ecosystem']}: {u['releases']} releases, "
                         f"{u['no_earlier_release']} with no earlier release, {u['errors']} "
                         f"diff errors, median {median} s. Rules in new findings: {rules}.")
    if scores.get("detonation_cost"):
        lines += ["", "### Detonation cost", "",
                  "| Ecosystem | Set | Detonated | Errors | Timed out | Median seconds | "
                  "Total seconds |", "|---|---|---|---|---|---|---|"]
        for c in scores["detonation_cost"]:
            median = "n/a" if c["median_seconds"] is None else c["median_seconds"]
            lines.append(f"| {c['ecosystem']} | {c['set']} | {c['packages']} | {c['errors']} | "
                         f"{c['timed_out']} | {median} | {c['total_seconds']} |")
    lines += ["", "Precision depends on the mix of malicious and benign packages here, which "
              "is not the mix in the wild; false positives per 1,000 benign releases do not. "
              "Most samples in the DataDog dataset were found by GuardDog, which favours it. "
              "No findings does not mean safe.", ""]
    return "\n".join(lines)

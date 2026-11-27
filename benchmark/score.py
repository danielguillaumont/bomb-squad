"""Scores from a results file: recall on malicious samples, false positives on benign
releases, and precision on this mixture, per ecosystem, split and surface, always with the
counts they come from."""

from __future__ import annotations

import json
from pathlib import Path

DETECTORS = (
    ("bombsquad", "high", "Bomb Squad, a high finding"),
    ("bombsquad", "review", "Bomb Squad, a review or high finding"),
    ("guarddog", "high_risk", "GuardDog, high risk"),
    ("guarddog", "suspicious", "GuardDog, suspicious or high risk"),
    ("guarddog", "any", "GuardDog, any rule (its exit code)"),
)
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


def flagged(row: dict, tool: str, threshold: str) -> bool | None:
    """True or False, or None when the tool failed on this package."""
    result = row.get(tool) or {}
    if result.get("error"):
        return None
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


def _rate(numerator: int, denominator: int) -> dict:
    return {"count": numerator, "of": denominator,
            "rate": round(numerator / denominator, 4) if denominator else None}


def _confusion(malicious: list[dict], benign: list[dict], tool: str, threshold: str) -> dict:
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
            for tool, threshold, label in DETECTORS:
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
            for tool, threshold, label in DETECTORS:
                hits = [flagged(r, tool, threshold) for r in members]
                out.setdefault("surfaces", []).append({
                    "ecosystem": ecosystem, "surface": surface, "tool": tool,
                    "threshold": threshold, "label": label,
                    "recall": _rate(hits.count(True), hits.count(True) + hits.count(False))})
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
    lines += ["", "Precision depends on the mix of malicious and benign packages here, which "
              "is not the mix in the wild; false positives per 1,000 benign releases do not. "
              "Most samples in the DataDog dataset were found by GuardDog, which favours it. "
              "No findings does not mean safe.", ""]
    return "\n".join(lines)

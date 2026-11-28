"""New releases of a fixed list of popular packages, each diffed against the release before
it, as `bombsquad diff` compares an update.

Nothing is installed or run: each release is fetched, checked against the registry's hash,
unpacked and scanned. A release is queued for review when the diff shows a new or changed
entry point, a new finding at review or high, or a publish signal at review. Being queued
is not a verdict, and a release that is not queued is not cleared: payloads can be fetched
at run time, gated on time or conditions, or hidden from static analysis.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from benchmark import benign, tools
from bombsquad.lockfiles import version_key
from bombsquad.registry import Fetch

# Every release in a daily window is recent, so release age says nothing about it.
AGE_SIGNALS = ("recent-release", "release-age")
Diff = Callable[[str, str, str, str], dict]


def new_releases(ecosystem: str, name: str, since: datetime, until: datetime, fetch: Fetch
                 ) -> list[dict]:
    """Stable versions first published in [since, until), each with the highest lower
    stable version published before it. Pre-releases are left out: an install without an
    exact version does not pick them."""
    published = benign.published_versions(ecosystem, name, fetch)
    out = []
    for moment, version in sorted(published):
        if not (since <= moment < until) or not benign.stable(version):
            continue
        key = version_key(version)
        earlier = [c for c in published if c[0] < moment and version_key(c[1]) < key
                   and benign.stable(c[1])]
        previous = benign.highest(earlier)
        out.append({"ecosystem": ecosystem, "name": name, "version": version,
                    "published": moment.isoformat(), "previous": previous[1] if previous
                    else None})
    return out


def reasons(diff: dict) -> list[str]:
    """Why a release is queued for review, from what the diff kept: kinds, rule IDs and
    signal names, never evidence."""
    out = []
    entries = diff.get("entry_points") or {}
    if entries.get("added") or entries.get("changed"):
        surfaces = ", ".join(entries.get("surfaces") or []) or "unknown surface"
        out.append(f"{entries.get('added', 0)} new and {entries.get('changed', 0)} changed "
                   f"entry points ({surfaces})")
    for level in ("high", "review"):
        rules = (diff.get("rules_by_level") or {}).get(level) or []
        if rules:
            out.append(f"new {level} findings: {', '.join(rules)}")
    for signal in diff.get("signals") or []:
        name, _, level = signal.rpartition(":")
        if level in ("review", "high") and name not in AGE_SIGNALS:
            out.append(f"publish signal: {name}")
    return out


def check(release: dict, diff: Diff = tools.bombsquad_diff) -> dict:
    """Diff one new release against the one before it and say whether to review it."""
    row = dict(release)
    if not row.get("previous"):
        row["status"] = "no earlier release to compare with"
        return row
    result = diff(row["ecosystem"], row["name"], row["previous"], row["version"])
    row["diff"] = result
    if result.get("error"):
        row["status"] = "error"
        return row
    row["reasons"] = reasons(result)
    row["status"] = "queued for review" if row["reasons"] else "nothing new found"
    return row


def markdown(meta: dict, rows: list[dict]) -> str:
    queued = [r for r in rows if r.get("status") == "queued for review"]
    errors = [r for r in rows if r.get("status") == "error"]
    lines = ["## Releases to review", "",
             f"Window {meta['since']} to {meta['until']}, {meta['packages']} packages, "
             f"{len(rows)} new releases, {len(queued)} queued for review, {len(errors)} "
             "that could not be compared.", "",
             "Queued is not a verdict: each needs a human review before anything is said "
             "about it. Not queued does not mean safe.", ""]
    if queued:
        lines += ["| Release | Compared with | Published | Why |", "|---|---|---|---|"]
        for r in queued:
            lines.append(f"| {r['ecosystem']}:{r['name']}@{r['version']} | {r['previous']} | "
                         f"{r['published']} | {'; '.join(r['reasons'])} |")
    if errors:
        lines += ["", "Could not be compared: " + ", ".join(
            f"{r['ecosystem']}:{r['name']}@{r['version']} ({r['diff']['error'][:80]})"
            for r in errors)]
    return "\n".join(lines) + "\n"


__all__ = ["check", "markdown", "new_releases", "reasons"]

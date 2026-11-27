"""Named incidents: each version an OpenSSF malicious-packages report confirms for an
incident in the roadmap, compared with the release published before it, as
`bombsquad diff` compares an update.

This is the roadmap's Phase 2 exit: the new entry point should be reported as a new
capability. It can only be checked where a public dataset still holds the artifact, since
the registries have removed these versions. A version missing from the dataset commit is
reported as such, not as a miss.
"""

from __future__ import annotations

import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

from benchmark import benign, samples
from bombsquad.archive import ArchiveError, unpack
from bombsquad.diff import compare, scan_side, unpack_release
from bombsquad.registry import Fetch, npm_releases, pypi_releases

REPORTS = "https://github.com/ossf/malicious-packages/blob/main/osv/malicious"


@dataclass(frozen=True)
class Incident:
    incident: str
    ecosystem: str  # npm | pypi
    package: str
    version: str
    published: str  # when the version was published: the registry's time, or the write-up's
    report: str  # OpenSSF malicious-packages ID
    surface: str  # where the write-up says it runs: npm (install scripts) or python

    @property
    def report_url(self) -> str:
        return f"{REPORTS}/{self.ecosystem}/{self.package}/{self.report}.json"


INCIDENTS = (
    # ChainDrop: Microsoft, 2026-08-04, names keyv, flat-cache and cache-manager; the
    # versions are those of the OpenSSF reports, the times the npm registry's.
    Incident("ChainDrop", "npm", "keyv", "6.0.0", "2026-08-04T09:35:00Z",
             "MAL-2026-11524", "npm"),
    Incident("ChainDrop", "npm", "flat-cache", "6.1.24", "2026-08-04T10:10:55Z",
             "MAL-2026-11971", "npm"),
    Incident("ChainDrop", "npm", "cache-manager", "7.2.10", "2026-08-04T10:14:41Z",
             "MAL-2026-11523", "npm"),
    # agent-framework: StepSecurity, 2026-11-18, gives the upload times.
    Incident("agent-framework", "pypi", "agent-framework", "1.26.1", "2026-11-17T20:35:20Z",
             "MAL-2026-20101", "python"),
    Incident("agent-framework", "pypi", "agent-framework", "1.26.2", "2026-11-17T21:08:39Z",
             "MAL-2026-20101", "python"),
)


def find(incidents: tuple[Incident, ...], listing: list[str]) -> dict[Incident, samples.Sample]:
    """The dataset sample for each incident version, where the listing has one."""
    by_version = {(s.ecosystem, s.name, s.version): s for s in samples.parse_listing(listing)}
    return {i: by_version[(i.ecosystem, i.package, i.version)] for i in incidents
            if (i.ecosystem, i.package, i.version) in by_version}


def _kind(ecosystem: str, filename: str) -> str:
    if filename.lower().endswith(".whl"):
        return "wheel"
    return "npm-tarball" if ecosystem == "npm" else "sdist"


def unpack_sample(sample: samples.Sample, dataset: Path, folder: Path) -> list[str]:
    """Decrypt a sample and lay out its artifacts as `unpack_release` does, in
    `folder/<kind>`, so its paths line up with a release from the registry. Returns notes."""
    data = (dataset / sample.path).read_bytes()
    decrypted, notes = unpack(data, Path(sample.path).name, folder / ".sample",
                              samples.PASSWORD)
    inner = [p for p in sorted(decrypted.rglob("*")) if p.is_file()
             and p.name.lower().endswith(samples.INNER_ARCHIVES)]
    if not inner:
        root = samples.package_root(sample.ecosystem, decrypted)
        wheel = sample.ecosystem == "pypi" and any(root.glob("*.dist-info"))
        kind = "wheel" if wheel else _kind(sample.ecosystem, "")
        shutil.move(root, folder / kind)
        return notes
    for archive in inner:
        kind = _kind(sample.ecosystem, archive.name)
        if (folder / kind).exists():
            notes.append(f"{archive.name}: a second {kind}, not compared")
            continue
        raw = folder / f".{kind}"
        try:
            unpacked, skipped = unpack(archive.read_bytes(), archive.name, raw)
        except ArchiveError as exc:
            notes.append(f"{archive.name}: {exc}")
            continue
        unpacked.rename(folder / kind)
        notes += [f"{archive.name}: {n}" for n in skipped]
    return notes


def _kinds(folder: Path) -> set[str]:
    return {p.name for p in folder.iterdir() if p.is_dir() and not p.name.startswith(".")}


def evaluate(incident: Incident, sample: samples.Sample | None, dataset: Path, work: Path,
             fetch: Fetch) -> dict:
    """Diff the incident version against the release published before it. Keeps entry
    point kinds, paths and rule IDs, not evidence or sample content."""
    row = {**asdict(incident), "report_url": incident.report_url,
           "sample": sample.path if sample else None}
    if sample is None:
        row["status"] = "not in the dataset"
        return row
    published = datetime.fromisoformat(incident.published.replace("Z", "+00:00"))
    previous = benign.release_on(incident.ecosystem, incident.package,
                                 published - timedelta(seconds=1), fetch)
    row["previous"] = previous
    if previous is None:
        row["status"] = "no earlier release on the registry"
        return row
    lookup = npm_releases if incident.ecosystem == "npm" else pypi_releases
    [release] = lookup(incident.package, [previous], fetch)
    old, new = work / "old", work / "new"
    old.mkdir(parents=True)
    new.mkdir(parents=True)
    unpack_release(release, old, fetch)
    notes = unpack_sample(sample, dataset, new)
    common = sorted(_kinds(old) & _kinds(new))
    row["artifacts"] = common
    if not common:
        row["status"] = "no artifact of the same kind to compare"
        return row
    for side in (old, new):
        for kind in _kinds(side) - set(common):
            shutil.rmtree(side / kind)
    roots = (old / common[0], new / common[0]) if len(common) == 1 else (old, new)
    report = compare(f"{incident.ecosystem}:{incident.package}@{previous}..{incident.version}",
                     scan_side(previous, roots[0], package=True),
                     scan_side(incident.version, roots[1], notes=notes, package=True))
    entries = [("added", e) for e in report.added_entries]
    entries += [("changed", b) for _, b in report.changed_entries]
    row["entry_points"] = [{"change": change, "surface": e.surface, "kind": e.kind,
                            "path": e.path} for change, e in entries]
    row["findings"] = {level: sorted({f.rule.id for f in report.added_findings
                                      if f.level.value == level})
                       for level in ("high", "review")}
    row["reported"] = any(e.surface == incident.surface for _, e in entries)
    row["status"] = "compared"
    return row


def markdown(rows: list[dict], dataset_commit: str) -> str:
    lines = ["## Named incidents", "",
             f"Each version an OpenSSF report confirms, compared with the release before it. "
             f"Dataset commit `{dataset_commit[:12]}`. Static analysis only; no findings "
             "does not mean safe.", "",
             "| Incident | Version | Report | Compared with | New or changed entry points "
             "| New high, review findings | New entry point reported |",
             "|---|---|---|---|---|---|---|"]
    for r in rows:
        name = f"{r['ecosystem']}:{r['package']}@{r['version']}"
        report = f"[{r['report']}]({r['report_url']})"
        if r["status"] != "compared":
            lines.append(f"| {r['incident']} | {name} | {report} | {r.get('previous') or '-'} "
                         f"| {r['status']} | - | - |")
            continue
        entries = "; ".join(f"{e['change']} {e['surface']}: {e['kind']} ({e['path']})"
                            for e in r["entry_points"]) or "none"
        findings = ", ".join(r["findings"]["high"]) or "none"
        findings += "; " + (", ".join(r["findings"]["review"]) or "none")
        lines.append(f"| {r['incident']} | {name} | {report} | {r['previous']} | {entries} "
                     f"| {findings} | {'yes' if r['reported'] else 'no'} |")
    return "\n".join(lines) + "\n"


__all__ = ["INCIDENTS", "Incident", "evaluate", "find", "markdown", "unpack_sample"]

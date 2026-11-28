"""OpenSSF malicious-packages reports for the benchmark's malicious samples.

DataDog's dataset says a sample was found malicious; an OpenSSF report is a second,
public confirmation with an ID that can be linked. Each sampled name and version is looked
up in the reports of a pinned commit. A report covers a version when it lists it, when its
range starts at that version with no end, or when it affects every version. Other ranges
are not evaluated, and such a sample counts as "name only", not as covered. Withdrawn
reports are left out.

Only report files are read, never package content. The repository is fetched without file
contents, as the dataset is, and only the sampled names' report folders are checked out.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = "ossf/malicious-packages"
COMMIT = "efc03f62e0d3b9bb0a9f1b4c76d24b7bab5ecd1b"
COMMIT_DATE = "2026-11-28"
ROOT = "osv/malicious"
COVERS = ("version", "all versions")
NAME = re.compile(r"(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+")
OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}


def registry_name(ecosystem: str, name: str) -> str:
    """The name as the registry and the reports write it. The dataset writes a scoped npm
    name `@scope@name`; PyPI names are compared normalized, as the reports' folders are."""
    if ecosystem == "npm" and name.startswith("@") and name.count("@") == 2:
        return "@" + name[1:].replace("@", "/", 1)
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def folder(ecosystem: str, name: str) -> str:
    return f"{ROOT}/{ecosystem}/{registry_name(ecosystem, name)}"


def paths(listing: list[str], wanted: list[tuple[str, str]]) -> list[str]:
    """The report files, from the repository's file listing, for the (ecosystem, name)
    pairs. Paths with anything but plain name characters are left out."""
    folders = {folder(e, n) + "/" for e, n in wanted}
    safe = re.compile(rf"^{ROOT}/(npm|pypi)/{NAME.pattern}/MAL-\d{{4}}-\d+\.json$")
    return sorted(p for p in (line.strip() for line in listing)
                  if safe.match(p) and p.rsplit("/", 1)[0] + "/" in folders)


def covers(report: dict, ecosystem: str, name: str, version: str) -> str | None:
    """"version" when the report lists this version, "all versions" when it affects every
    version, "name" when it names the package but not, or not plainly, this version."""
    if report.get("withdrawn"):
        return None
    found = None
    for affected in report.get("affected") or []:
        package = affected.get("package") or {}
        if (package.get("ecosystem") != OSV_ECOSYSTEM[ecosystem]
                or registry_name(ecosystem, str(package.get("name") or ""))
                != registry_name(ecosystem, name)):
            continue
        if version in (affected.get("versions") or []):
            return "version"
        for r in affected.get("ranges") or []:
            events = r.get("events") or []
            if events == [{"introduced": version}]:
                return "version"  # from this version on, with no end
            if events == [{"introduced": "0"}]:
                found = "all versions"
        found = found or "name"
    return found


def lookup(root: Path, ecosystem: str, name: str, version: str) -> dict:
    """The reports in a checkout of the repository that name this package, and how the
    best of them covers this version."""
    rank = {"version": 0, "all versions": 1, "name": 2}
    reports, best = [], None
    plain = registry_name(ecosystem, name)
    if not NAME.fullmatch(plain) or plain.split("/")[-1] in (".", ".."):
        return {"reports": [], "covers": None}
    directory = root / folder(ecosystem, name)
    for path in sorted(directory.glob("MAL-*.json")) if directory.is_dir() else []:
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        how = covers(report, ecosystem, name, version)
        if how is None:
            continue
        reports.append(str(report.get("id") or path.stem))
        if best is None or rank[how] < rank[best]:
            best = how
    return {"reports": reports, "covers": best}


def report_url(ecosystem: str, name: str, report_id: str) -> str:
    return f"https://github.com/{REPO}/blob/{COMMIT}/{folder(ecosystem, name)}/{report_id}.json"


__all__ = ["COMMIT", "COMMIT_DATE", "COVERS", "REPO", "covers", "folder", "lookup", "paths",
           "registry_name", "report_url"]

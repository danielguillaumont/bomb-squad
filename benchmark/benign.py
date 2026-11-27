"""Benign releases: popular npm and PyPI packages, each at the release that was current on
a fixed date.

The popular lists are pinned: npm's from the `npm-high-impact` package at a fixed version
(its list of the most-downloaded packages), PyPI's from hugovk/top-pypi-packages at a fixed
commit (30-day download counts). Both are read as data. Packages are sampled from the top
of each list with a fixed seed. "Popular" is not "benign": a compromised release of a
popular package would be counted as benign here, which the write-up says.
"""

from __future__ import annotations

import base64
import json
import random
import re
import urllib.parse
from datetime import datetime
from pathlib import Path

from bombsquad.archive import unpack
from bombsquad.diff import unpack_release
from bombsquad.lockfiles import version_key
from bombsquad.registry import (
    MAX_METADATA_BYTES,
    NPM_REGISTRY,
    PYPI,
    Fetch,
    FetchError,
    download,
    npm_releases,
    pypi_releases,
)

NPM_LIST_PACKAGE = "npm-high-impact"
NPM_LIST_VERSION = "1.13.0"
NPM_LIST_FILE = "lib/top-download.js"
PYPI_LIST_REPO = "hugovk/top-pypi-packages"
PYPI_LIST_COMMIT = "29c0d4c38c28c0e6b99e73fa09cb91a2323ca51b"  # 2026-11-01
PYPI_LIST_FILE = "top-pypi-packages.min.json"
_NAME = re.compile(r"'((?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+)'")
_PRERELEASE = re.compile(r"(?:a|b|rc|dev|alpha|beta|pre|preview)\d*|-", re.IGNORECASE)


def npm_names_from(text: str) -> list[str]:
    seen: dict[str, None] = {}
    for name in _NAME.findall(text):
        seen.setdefault(name, None)
    return list(seen)


def npm_popular(fetch: Fetch, work: Path) -> list[str]:
    [release] = npm_releases(NPM_LIST_PACKAGE, [NPM_LIST_VERSION], fetch)
    data = download(release.artifacts[0], fetch)  # checked against the registry's hash
    root, _ = unpack(data, release.artifacts[0].filename, work / "npm-list")
    return npm_names_from((root / NPM_LIST_FILE).read_text(encoding="utf-8"))


def pypi_names_from(text: str) -> list[str]:
    rows = json.loads(text).get("rows", [])
    return [r["project"] for r in rows if isinstance(r, dict) and isinstance(
        r.get("project"), str)]


def pypi_popular(fetch: Fetch) -> list[str]:
    url = (f"https://api.github.com/repos/{PYPI_LIST_REPO}/contents/{PYPI_LIST_FILE}"
           f"?ref={PYPI_LIST_COMMIT}")
    document = json.loads(fetch(url, MAX_METADATA_BYTES))
    return pypi_names_from(base64.b64decode(document["content"]).decode("utf-8"))


def sample_names(names: list[str], top: int, count: int, seed: int, ecosystem: str,
                 exclude: frozenset[str] = frozenset()) -> list[str]:
    pool = [name for name in names[:top] if name not in exclude]
    return random.Random(f"{seed}:benign:{ecosystem}").sample(pool, min(count, len(pool)))


def _stable(version: str) -> bool:
    return not _PRERELEASE.search(version.split("+", 1)[0])


def _parse(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else None


def release_on(ecosystem: str, name: str, as_of: datetime, fetch: Fetch) -> str | None:
    """The highest stable version published on or before `as_of`, or the highest
    pre-release for a package that has only ever published pre-releases (OpenTelemetry's
    instrumentation packages are all 0.xbN)."""
    if ecosystem == "npm":
        url = f"{NPM_REGISTRY}/{urllib.parse.quote(name, safe='@')}"
        document = json.loads(fetch(url, MAX_METADATA_BYTES))
        times = document.get("time") if isinstance(document.get("time"), dict) else {}
        versions = document.get("versions") if isinstance(document.get("versions"), dict) else {}
        candidates = [(t, v) for v, t in ((v, _parse(times.get(v))) for v in versions)
                      if t and t <= as_of]
    else:
        url = f"{PYPI}/pypi/{urllib.parse.quote(name, safe='')}/json"
        document = json.loads(fetch(url, MAX_METADATA_BYTES))
        releases = document.get("releases") if isinstance(document.get("releases"), dict) else {}
        candidates = []
        for version, files in releases.items():
            files = [f for f in files if isinstance(f, dict) and not f.get("yanked")]
            times = [t for t in (_parse(f.get("upload_time_iso_8601")) for f in files) if t]
            if times and min(times) <= as_of:
                candidates.append((min(times), version))
    # The highest version, not the latest upload: maintainers publish backports to old
    # majors (semver 5.7.x after 7.x), which were never the current release.
    candidates = [c for c in candidates if _stable(c[1])] or candidates
    return max(candidates, key=lambda c: version_key(c[1]))[1] if candidates else None


def fetch_release(ecosystem: str, name: str, version: str, folder: Path, fetch: Fetch
                  ) -> Path:
    """Download and unpack one release as `bombsquad diff` would. Returns the folder to
    scan."""
    lookup = npm_releases if ecosystem == "npm" else pypi_releases
    [release] = lookup(name, [version], fetch)
    folder.mkdir(parents=True, exist_ok=True)
    root, _ = unpack_release(release, folder, fetch)
    return root


__all__ = ["FetchError", "fetch_release", "npm_popular", "pypi_popular", "release_on",
           "sample_names"]

"""A published version against its source: the release tag in the declared GitHub
repository, the files the package has that the repository does not, and tags that moved.

GitHub is asked over its public API, without credentials, so it allows a limited number of
requests an hour. The repository's archive is unpacked with the same rules as a package
and nothing in it is run. GitHub generates archives on request and publishes no hash for
them, so unlike registry artifacts they cannot be checked against one.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from bombsquad.archive import ArchiveError, unpack
from bombsquad.discovery import LANGUAGE_BY_SUFFIX
from bombsquad.model import Level, Signal
from bombsquad.registry import MAX_ARTIFACT_BYTES, MAX_METADATA_BYTES, Fetch, FetchError, Release

GITHUB_API = "https://api.github.com"
CODELOAD = "https://codeload.github.com"
_GITHUB = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?(?:[#?].*)?$",
                     re.IGNORECASE)
_SHORT = re.compile(r"^(?:github:)?([\w.-]+)/([\w.-]+)$")
# Files registries write into the artifact that a repository does not have.
GENERATED = re.compile(r"(?:^|/)(?:PKG-INFO|[^/]+\.egg-info/.*|setup\.cfg)$")


@dataclass
class SourceCheck:
    repository: str | None = None  # owner/name
    tag: str | None = None
    commit: str | None = None
    compared: str | None = None  # the commit whose files were compared
    signals: list[Signal] = field(default_factory=list)
    only_in_artifact: list[str] = field(default_factory=list)
    differs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"repository": self.repository, "tag": self.tag, "commit": self.commit,
                "compared": self.compared, "only_in_artifact": self.only_in_artifact,
                "differs": self.differs, "notes": self.notes}


def github_repository(url: str | None) -> tuple[str, str] | None:
    if not url:
        return None
    match = _GITHUB.search(url) or _SHORT.match(url)
    return (match.group(1), match.group(2)) if match else None


def tag_candidates(name: str, version: str) -> list[str]:
    short = name.rsplit("/", 1)[-1]
    out: list[str] = []
    for tag in (f"v{version}", version, f"{name}@{version}", f"{short}@{version}",
                f"{short}-v{version}", f"{short}-{version}"):
        if tag not in out:
            out.append(tag)
    return out


def _json(fetch: Fetch, url: str) -> dict:
    try:
        data = json.loads(fetch(url, MAX_METADATA_BYTES))
    except ValueError:
        raise FetchError(f"{url}: not JSON") from None
    if not isinstance(data, dict):
        raise FetchError(f"{url}: unexpected response")
    return data


def tag_commit(owner: str, repo: str, tag: str, fetch: Fetch) -> str | None:
    """The commit a tag points at, following annotated tags, or None if there is no such
    tag."""
    base = f"{GITHUB_API}/repos/{owner}/{repo}/git"
    try:
        ref = _json(fetch, f"{base}/ref/tags/{urllib.parse.quote(tag, safe='/@')}")
    except FetchError as exc:
        if exc.status == 404:
            return None
        raise
    target = ref.get("object") if isinstance(ref.get("object"), dict) else {}
    for _ in range(5):  # a tag of a tag is allowed; stop after a few
        if target.get("type") != "tag":
            break
        tag_object = _json(fetch, f"{base}/tags/{target.get('sha')}")
        target = tag_object.get("object") if isinstance(tag_object.get("object"), dict) else {}
    sha = target.get("sha")
    return sha if target.get("type") == "commit" and isinstance(sha, str) else None


def commit_identity(owner: str, repo: str, sha: str, fetch: Fetch) -> dict:
    data = _json(fetch, f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}")
    commit = data.get("commit") if isinstance(data.get("commit"), dict) else {}
    author = commit.get("author") if isinstance(commit.get("author"), dict) else {}
    message = commit.get("message") if isinstance(commit.get("message"), str) else ""
    return {"commit": sha, "author": author.get("name"), "date": author.get("date"),
            "subject": message.splitlines()[0][:200] if message else ""}


def _files(root: Path) -> dict[str, str]:
    """Relative path -> hash of the content with line endings normalised."""
    out = {}
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            data = path.read_bytes().replace(b"\r\n", b"\n")
            out[path.relative_to(root).as_posix()] = hashlib.sha256(data).hexdigest()
    return out


def compare_to_source(release: Release, tree: Path | None, reached: set[str],
                      fetch: Fetch, record: Path | None = None,
                      now: datetime | None = None, prefix: str = "") -> SourceCheck:
    """Check the new version against its declared GitHub repository. `tree` is the unpacked
    artifact that mirrors the source tree (the npm tarball, or the sdist), or None when
    there is none; `reached` lists the files entry points run, relative to `tree`; `prefix`
    is how `tree` is shown in the report."""
    check = SourceCheck()
    found = github_repository(release.repository)
    if found is None:
        check.notes.append("No GitHub repository is declared, so the package was not compared "
                           "with its source.")
        return check
    owner, repo = found
    check.repository = f"{owner}/{repo}"
    try:
        for tag in tag_candidates(release.name, release.version):
            commit = tag_commit(owner, repo, tag, fetch)
            if commit:
                check.tag, check.commit = tag, commit
                break
        if check.tag is None:
            check.signals.append(Signal(
                "no-matching-tag", Level.INFO,
                f"{check.repository} has none of the tags "
                f"{', '.join(tag_candidates(release.name, release.version))}, so this "
                "version cannot be tied to a commit there"))
        if release.git_head and check.commit and release.git_head != check.commit:
            check.signals.append(Signal(
                "tag-not-at-published-commit", Level.REVIEW,
                f"npm recorded commit {release.git_head[:12]} at publish time, but tag "
                f"{check.tag} points at {check.commit[:12]}"))
        if record is not None and check.tag and check.commit:
            check.signals += _history(record, check, owner, repo, fetch, now)
        ref = check.commit or release.git_head
        if not ref:
            check.notes.append("No tag or recorded commit to compare the files with.")
        elif tree is None:
            check.notes.append("There is no sdist to compare with the source.")
        elif ref:
            _compare_files(check, release, tree, reached, prefix, owner, repo, ref, fetch)
    except FetchError as exc:
        check.notes.append(f"GitHub could not be read ({exc}); the source comparison is "
                           "incomplete.")
    return check


def _compare_files(check: SourceCheck, release: Release, tree: Path, reached: set[str],
                   prefix: str, owner: str, repo: str, ref: str, fetch: Fetch) -> None:
    data = fetch(f"{CODELOAD}/{owner}/{repo}/tar.gz/{ref}", MAX_ARTIFACT_BYTES)
    with tempfile.TemporaryDirectory(prefix="bombsquad-source-",
                                     ignore_cleanup_errors=True) as work:
        try:
            root, skipped = unpack(data, f"{repo}.tar.gz", Path(work))
        except ArchiveError as exc:
            check.notes.append(f"The repository archive could not be unpacked: {exc}")
            return
        check.notes += [f"source archive: {n}" for n in skipped[:5]]
        if release.directory:
            root = root / release.directory
        source = _files(root) if root.is_dir() else {}
    artifact = _files(tree)
    only = sorted(p for p in artifact if p not in source and not GENERATED.search(p)
                  and p != "package.json")
    differs = sorted(p for p in artifact if p in source and artifact[p] != source[p]
                     and p != "package.json")
    check.compared = ref
    check.only_in_artifact = [prefix + p for p in only]
    check.differs = [prefix + p for p in differs]
    where = f"{check.repository} at {check.tag or ref[:12]}"
    code_only = [p for p in only if Path(p).suffix.lower() in LANGUAGE_BY_SUFFIX]
    for label, paths, verb in (("only-in-artifact", code_only, "are not in"),
                               ("differs-from-source", differs, "differ from")):
        if not paths:
            continue
        run = [p for p in paths if p in reached]
        shown = run or paths
        names = ", ".join(prefix + p for p in shown[:5])
        more = f" and {len(shown) - 5} more" if len(shown) > 5 else ""
        detail = f"{len(paths)} code file{'s' if len(paths) != 1 else ''} {verb} {where}"
        if run:
            detail += f", including {len(run)} that entry points run: {names}{more}"
        else:
            detail += f": {names}{more}"
        check.signals.append(Signal(label, Level.REVIEW if run else Level.INFO, detail))


def _history(record: Path, check: SourceCheck, owner: str, repo: str, fetch: Fetch,
             now: datetime | None) -> list[Signal]:
    """Compare the tag with earlier observations, then add this one. Observations are
    only ever appended."""
    try:
        data = json.loads(record.read_text(encoding="utf-8")) if record.exists() else {}
    except (OSError, ValueError) as exc:
        check.notes.append(f"The tag record {record} could not be read ({exc}), so tag "
                           "history was not checked and nothing was added to it.")
        return []
    if not isinstance(data, dict) or not isinstance(data.get("tags", {}), dict):
        check.notes.append(f"The tag record {record} is not in the expected format, so tag "
                           "history was not checked and nothing was added to it.")
        return []
    observations = data.setdefault("tags", {}).setdefault(f"github.com/{owner}/{repo}",
                                                         {}).setdefault(check.tag, [])
    identity = commit_identity(owner, repo, check.commit, fetch)
    signals = []
    earlier = [o for o in observations if o.get("commit") != check.commit]
    if earlier:
        first = earlier[0]
        same = first.get("author") == identity["author"] and first.get("date") == (
            identity["date"])
        if same:
            signals.append(Signal(
                "commit-rewritten", Level.HIGH,
                f"tag {check.tag} pointed at {str(first.get('commit'))[:12]} when recorded "
                f"on {first.get('seen')}, and now at {check.commit[:12]}, a different commit "
                f"with the same author ({identity['author']}) and date ({identity['date']})"))
        else:
            signals.append(Signal(
                "tag-moved", Level.REVIEW,
                f"tag {check.tag} pointed at {str(first.get('commit'))[:12]} when recorded "
                f"on {first.get('seen')}, and now points at {check.commit[:12]}"))
    if not observations or observations[-1].get("commit") != check.commit:
        observations.append({**identity, "seen": (now or datetime.now(UTC)).isoformat(
            timespec="seconds")})
        record.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return signals

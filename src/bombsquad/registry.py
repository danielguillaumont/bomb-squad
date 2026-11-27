"""Release metadata and artifacts from the npm and PyPI registries.

Only HTTPS requests to the registries' own hosts are made, redirects included. Every
artifact is checked against the hash the registry publishes for it before it is opened.
Nothing is installed, built or run.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from bombsquad import __version__

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI = "https://pypi.org"
ALLOWED_HOSTS = frozenset({"registry.npmjs.org", "pypi.org", "files.pythonhosted.org"})
MAX_METADATA_BYTES = 200 * 1024 * 1024  # full npm documents of large packages are big
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
TIMEOUT_SECONDS = 60


class FetchError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


Fetch = Callable[[str, int], bytes]  # (url, byte limit) -> body


def check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise FetchError(f"refusing to fetch {parts.scheme}://{parts.hostname}: only HTTPS to "
                         f"{', '.join(sorted(ALLOWED_HOSTS))}")


class _Redirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url: str, limit: int) -> bytes:
    """GET a URL from an allowed host, refusing bodies over `limit` bytes."""
    check_url(url)
    opener = urllib.request.build_opener(_Redirects)
    request = urllib.request.Request(url, headers={"User-Agent": f"bombsquad/{__version__}",
                                                   "Accept": "application/json"})
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            chunks, total = [], 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > limit:
                    raise FetchError(f"{url} is larger than {limit // (1024 * 1024)} MB")
                chunks.append(chunk)
            return b"".join(chunks)
    except urllib.error.HTTPError as exc:
        raise FetchError(f"{url}: HTTP {exc.code}", exc.code) from None
    except urllib.error.URLError as exc:
        raise FetchError(f"{url}: {exc.reason}") from None


@dataclass
class Artifact:
    kind: str  # npm tarball | sdist | wheel
    filename: str
    url: str
    algorithm: str  # sha512 | sha256 | sha1
    digest: str  # hex
    provenance: bool | None = None  # None when the registry was not asked or did not say


@dataclass
class Release:
    ecosystem: str  # npm | pypi
    name: str
    version: str
    published: datetime | None  # the registry's publish time for this version
    artifacts: list[Artifact]
    publisher: str | None = None  # the account that published it, where the registry says
    maintainers: list[str] | None = None
    repository: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def provenance(self) -> bool | None:
        values = [a.provenance for a in self.artifacts]
        if any(v is None for v in values) or not values:
            return None
        return all(values)


def verify(artifact: Artifact, data: bytes) -> None:
    actual = hashlib.new(artifact.algorithm, data).hexdigest()
    if actual != artifact.digest:
        raise FetchError(f"{artifact.filename}: {artifact.algorithm} does not match the "
                         f"registry ({actual[:16]}… instead of {artifact.digest[:16]}…); "
                         "not opened")


def download(artifact: Artifact, fetch: Fetch = http_get) -> bytes:
    check_url(artifact.url)
    data = fetch(artifact.url, MAX_ARTIFACT_BYTES)
    verify(artifact, data)
    return data


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _repository(value: object) -> str | None:
    if isinstance(value, dict):
        value = value.get("url")
    return value if isinstance(value, str) and value else None


# npm ---------------------------------------------------------------------------------------

def npm_releases(name: str, versions: list[str], fetch: Fetch = http_get) -> list[Release]:
    url = f"{NPM_REGISTRY}/{urllib.parse.quote(name, safe='@')}"
    try:
        document = json.loads(fetch(url, MAX_METADATA_BYTES))
    except ValueError:
        raise FetchError(f"{url}: not JSON") from None
    known = document.get("versions") if isinstance(document, dict) else None
    times = document.get("time") if isinstance(document.get("time"), dict) else {}
    out = []
    for version in versions:
        manifest = known.get(version) if isinstance(known, dict) else None
        if not isinstance(manifest, dict):
            raise FetchError(f"{name}@{version} is not in the npm registry")
        dist = manifest.get("dist") if isinstance(manifest.get("dist"), dict) else {}
        tarball = dist.get("tarball")
        if not isinstance(tarball, str):
            raise FetchError(f"{name}@{version} has no tarball")
        integrity = dist.get("integrity") if isinstance(dist.get("integrity"), str) else ""
        sha512 = next((part[len("sha512-"):] for part in integrity.split()
                       if part.startswith("sha512-")), None)
        notes = []
        if sha512:
            algorithm, digest = "sha512", base64.b64decode(sha512).hex()
        elif isinstance(dist.get("shasum"), str):
            algorithm, digest = "sha1", dist["shasum"].lower()
            notes.append("The registry gives only a SHA-1 checksum for this version.")
        else:
            raise FetchError(f"{name}@{version} has no checksum in the registry")
        attestations = dist.get("attestations")
        artifact = Artifact("npm tarball", tarball.rsplit("/", 1)[-1], tarball, algorithm,
                            digest, provenance=isinstance(attestations, dict) and bool(
                                attestations.get("provenance")))
        user = manifest.get("_npmUser")
        people = manifest.get("maintainers")
        out.append(Release(
            "npm", name, version, _time(times.get(version)), [artifact],
            publisher=user.get("name") if isinstance(user, dict) else None,
            maintainers=sorted({p.get("name") for p in people if isinstance(p, dict)
                                and isinstance(p.get("name"), str)})
            if isinstance(people, list) else None,
            repository=_repository(manifest.get("repository")), notes=notes))
    return out


# PyPI --------------------------------------------------------------------------------------

def _pick(files: list[dict]) -> list[dict]:
    """The sdist, which carries setup.py and build hooks, and one wheel, which can carry
    .pth files: a pure-Python wheel when there is one."""
    sdists = [f for f in files if f.get("packagetype") == "sdist"]
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
    wheels.sort(key=lambda f: (not str(f.get("filename", "")).endswith("-none-any.whl"),
                               str(f.get("filename", ""))))
    return sdists[:1] + wheels[:1]


def pypi_releases(name: str, versions: list[str], fetch: Fetch = http_get) -> list[Release]:
    out = []
    for version in versions:
        url = (f"{PYPI}/pypi/{urllib.parse.quote(name, safe='')}/"
               f"{urllib.parse.quote(version, safe='')}/json")
        try:
            document = json.loads(fetch(url, MAX_METADATA_BYTES))
        except FetchError as exc:
            if exc.status == 404:
                raise FetchError(f"{name} {version} is not on PyPI") from None
            raise
        except ValueError:
            raise FetchError(f"{url}: not JSON") from None
        files = [f for f in document.get("urls", []) if isinstance(f, dict)]
        chosen = _pick(files)
        if not chosen:
            raise FetchError(f"{name} {version} has no sdist or wheel on PyPI")
        artifacts = []
        for f in chosen:
            digest = (f.get("digests") or {}).get("sha256")
            if not isinstance(digest, str) or not isinstance(f.get("url"), str):
                raise FetchError(f"{f.get('filename')} has no SHA-256 on PyPI")
            artifacts.append(Artifact(
                "sdist" if f.get("packagetype") == "sdist" else "wheel", str(f["filename"]),
                f["url"], "sha256", digest.lower(),
                provenance=_pypi_provenance(name, version, str(f["filename"]), fetch)))
        info = document.get("info") if isinstance(document.get("info"), dict) else {}
        urls = info.get("project_urls") if isinstance(info.get("project_urls"), dict) else {}
        repository = next((v for k, v in urls.items() if isinstance(v, str) and k.lower() in (
            "source", "repository", "source code", "code", "github")), None)
        uploaded = [t for t in (_time(f.get("upload_time_iso_8601")) for f in files) if t]
        out.append(Release("pypi", name, version, min(uploaded) if uploaded else None,
                           artifacts, repository=repository, notes=[
                               "PyPI does not publish who uploaded a release."]))
    return out


def _pypi_provenance(name: str, version: str, filename: str, fetch: Fetch) -> bool | None:
    url = (f"{PYPI}/integrity/{urllib.parse.quote(name, safe='')}/"
           f"{urllib.parse.quote(version, safe='')}/{urllib.parse.quote(filename, safe='')}/"
           "provenance")
    try:
        document = json.loads(fetch(url, MAX_METADATA_BYTES))
    except FetchError as exc:
        return False if exc.status == 404 else None
    except ValueError:
        return None
    bundles = document.get("attestation_bundles") if isinstance(document, dict) else None
    return bool(bundles)

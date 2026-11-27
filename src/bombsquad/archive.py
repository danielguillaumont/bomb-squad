"""Unpack a package archive (npm tarball, sdist, wheel) into a folder for scanning.

Only regular files are written. Links, devices, absolute paths, `..`, drive letters and
names Windows cannot hold are skipped and reported, so nothing lands outside the folder and
the same archive unpacks the same way on every OS. Member counts and sizes are capped,
counting the bytes actually decompressed. Nothing in the archive is run.
"""

from __future__ import annotations

import io
import re
import tarfile
import zipfile
from pathlib import Path

MAX_MEMBERS = 20_000
MAX_TOTAL_BYTES = 500 * 1024 * 1024
_RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?$", re.IGNORECASE)
_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')


class ArchiveError(Exception):
    """An archive that cannot be unpacked safely."""


def safe_name(name: str) -> str | None:
    """A relative path that stays inside the folder, or None."""
    name = name.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." or _BAD_CHARS.search(p) or _RESERVED.match(p) or
                        p != p.rstrip(". ") for p in parts):
        return None
    return "/".join(parts)


class _Writer:
    def __init__(self, dest: Path) -> None:
        self.dest = dest.resolve()
        self.notes: list[str] = []
        self.total = 0
        self.count = 0
        self.seen: set[str] = set()

    def skip(self, name: str, why: str) -> None:
        if len(self.notes) < 50:
            self.notes.append(f"{name!r} was not unpacked: {why}.")
        elif len(self.notes) == 50:
            self.notes.append("Further skipped members are not listed.")

    def write(self, raw: str, stream) -> None:
        self.count += 1
        if self.count > MAX_MEMBERS:
            raise ArchiveError(f"more than {MAX_MEMBERS} files")
        name = safe_name(raw)
        if name is None:
            self.skip(raw, "its path is absolute, leaves the folder or is not a valid name")
            return
        if name.lower() in self.seen:
            self.skip(raw, "another member has the same name, ignoring case")
            return
        self.seen.add(name.lower())
        target = (self.dest / name).resolve()
        if not target.is_relative_to(self.dest):
            self.skip(raw, "its path leaves the folder")
            return
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            out = open(target, "wb")  # noqa: SIM115 - closed below; errors skip the member
        except OSError as exc:
            self.skip(raw, f"it cannot be written here ({exc.strerror or exc})")
            return
        with out:
            while chunk := stream.read(1024 * 1024):
                self.total += len(chunk)
                if self.total > MAX_TOTAL_BYTES:
                    raise ArchiveError(f"more than {MAX_TOTAL_BYTES // (1024 * 1024)} MB "
                                       "when unpacked")
                out.write(chunk)


def unpack(data: bytes, filename: str, dest: Path, password: bytes | None = None
           ) -> tuple[Path, list[str]]:
    """Unpack into `dest`. Returns the package root (the single top folder npm tarballs
    and sdists wrap their files in, when there is one) and notes on skipped members.
    `password` opens a ZIP encrypted the traditional way, as malware datasets are."""
    writer = _Writer(dest)
    lower = filename.lower()
    try:
        if lower.endswith((".whl", ".zip")):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    if (info.external_attr >> 16) & 0o170000 == 0o120000:
                        writer.skip(info.filename, "it is a symbolic link")
                        continue
                    with archive.open(info, pwd=password) as stream:
                        writer.write(info.filename, stream)
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                for member in archive:
                    if member.isdir():
                        continue
                    if not member.isfile():
                        writer.skip(member.name, "it is a link or special file")
                        continue
                    stream = archive.extractfile(member)
                    if stream is not None:
                        writer.write(member.name, stream)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError, RuntimeError,
            NotImplementedError) as exc:
        # RuntimeError: encrypted without the right password; NotImplementedError: an
        # encryption or compression method zipfile does not support.
        raise ArchiveError(f"{filename}: {exc}") from None
    children = list(writer.dest.iterdir())
    root = children[0] if len(children) == 1 and children[0].is_dir() else writer.dest
    return root, writer.notes

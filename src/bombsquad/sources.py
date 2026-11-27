"""Find input files and decode them without changing a single character."""

from __future__ import annotations

import codecs
import os
from collections.abc import Iterable
from pathlib import Path

POWERSHELL_SUFFIXES = frozenset({".ps1", ".psm1", ".psd1"})
SKIPPED_DIRS = frozenset({".git", "node_modules", ".venv", "__pycache__"})
MAX_FILE_BYTES = 5 * 1024 * 1024


class InputError(Exception):
    """A path that cannot be scanned."""


def collect_files(paths: Iterable[Path]) -> list[tuple[Path, bool]]:
    """Every file under the given paths, in a stable order, each marked True when it was
    named on the command line rather than found in a directory."""
    files: list[tuple[Path, bool]] = []
    for path in paths:
        if path.is_dir():
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(d for d in dirs if d not in SKIPPED_DIRS)
                # Symlinked files are skipped: a link to ~/.aws/credentials inside a scanned
                # repository would otherwise be read, and could surface in evidence.
                files.extend((Path(root, name), False) for name in sorted(names)
                             if not Path(root, name).is_symlink())
        elif path.is_file():
            files.append((path, True))
        else:
            raise InputError(f"not found: {path}")
    return files


def decode(data: bytes) -> tuple[str, str]:
    """Decode script bytes the way PowerShell would, keeping line endings as they are.

    Returns the text and the encoding used. BOM-less files that are not valid UTF-8
    are read as Windows-1252, which is how Windows PowerShell 5.1 reads them.
    """
    for bom, name in (
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF32_LE, "utf-32"),
        (codecs.BOM_UTF32_BE, "utf-32"),
        (codecs.BOM_UTF16_LE, "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16"),
    ):
        if data.startswith(bom):
            return data.decode(name), name
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace"), "cp1252"


def read_source(path: Path) -> tuple[str, str]:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise InputError(f"larger than {MAX_FILE_BYTES // (1024 * 1024)} MB, not scanned")
    return decode(path.read_bytes())


def display_path(path: Path) -> str:
    """A forward-slash path relative to the working directory when possible."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()

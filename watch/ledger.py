"""Append-only, hash-chained JSON Lines files: the flag log and the defusal record.

Each entry carries its sequence number, the time it was recorded, the hash of the entry
before it and its own hash, a SHA-256 of the entry's canonical JSON. Rewriting, dropping or
reordering an entry breaks the chain from that entry on, and anyone who kept an earlier
head (its sequence number and hash) can check that it is still part of the chain. The chain
shows that the file was not changed, not that what it records is right.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

GENESIS = "0" * 64
RESERVED = ("seq", "recorded", "prev", "hash")


class LedgerError(Exception):
    """The file is not a valid chain, or an entry would not keep it one."""


def digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _moment(text: object, where: str) -> datetime:
    if not isinstance(text, str):
        raise LedgerError(f"{where}: no recorded time")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as exc:
        raise LedgerError(f"{where}: recorded time {text!r} is not ISO 8601") from exc
    if moment.tzinfo is None:
        raise LedgerError(f"{where}: recorded time has no time zone")
    return moment


def verify(path: Path) -> list[dict]:
    """The entries, in order, after checking the whole chain. A missing file is empty."""
    if not path.exists():
        return []
    entries: list[dict] = []
    previous, last_time = GENESIS, None
    for number, line in enumerate(path.read_text(encoding="utf-8").split("\n"), start=1):
        if not line:
            continue
        where = f"{path.name} line {number}"
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LedgerError(f"{where}: not JSON") from exc
        if not isinstance(entry, dict):
            raise LedgerError(f"{where}: not an object")
        if entry.get("seq") != len(entries) + 1:
            raise LedgerError(f"{where}: entry {entry.get('seq')!r} where "
                              f"{len(entries) + 1} was expected")
        if entry.get("prev") != previous:
            raise LedgerError(f"{where}: does not follow the entry before it")
        if entry.get("hash") != digest(entry):
            raise LedgerError(f"{where}: its hash does not match its content")
        moment = _moment(entry.get("recorded"), where)
        if last_time and moment < last_time:
            raise LedgerError(f"{where}: recorded before the entry before it")
        entries.append(entry)
        previous, last_time = entry["hash"], moment
    return entries


def head(entries: list[dict]) -> tuple[int, str]:
    return (entries[-1]["seq"], entries[-1]["hash"]) if entries else (0, GENESIS)


def check_head(entries: list[dict], seq: int, expected: str) -> None:
    """Raise unless entry `seq` still has the hash someone kept for it."""
    if seq == 0 and expected == GENESIS:
        return
    if not 1 <= seq <= len(entries):
        raise LedgerError(f"entry {seq} is no longer in the file")
    if entries[seq - 1]["hash"] != expected:
        raise LedgerError(f"entry {seq} has changed since its hash was kept")


def append(path: Path, record: dict, now: datetime | None = None) -> dict:
    """Add one entry after checking the chain, and return it."""
    clash = [k for k in RESERVED if k in record]
    if clash:
        raise LedgerError(f"the ledger sets {', '.join(clash)} itself")
    entries = verify(path)
    seq, previous = head(entries)
    moment = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    if entries and moment < _moment(entries[-1]["recorded"], path.name):
        raise LedgerError("the clock is behind the last entry")
    entry = {"seq": seq + 1, "recorded": moment.isoformat(), "prev": previous, **record}
    entry["hash"] = digest(entry)
    line = json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as out:
        if entries and path.stat().st_size and not path.read_bytes().endswith(b"\n"):
            out.write(b"\n")
        out.write(line.encode("utf-8"))
        out.flush()
        os.fsync(out.fileno())
    return entry


__all__ = ["GENESIS", "LedgerError", "append", "check_head", "digest", "head", "verify"]

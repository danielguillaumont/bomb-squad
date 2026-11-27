"""Read the strace log of one detonation: processes, files opened and network attempts.

The log comes from `strace -f -tt -q -s 256`, run as root so the traced package cannot
write to it. Lines look like `PID HH:MM:SS.ffffff syscall(args) = result`; a call another
thread interrupts is split into `<unfinished ...>` and `<... name resumed>` halves.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

_LINE = re.compile(r"^(\d+)\s+(\d\d:\d\d:\d\d\.\d+)\s+(.*)$")
_CALL = re.compile(r"^(\w+)\((.*)\)\s+=\s+(-?\d+|\?)(?:\s+(\w+))?")
_RESUMED = re.compile(r"^<\.\.\. (\w+) resumed>(.*)$")
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"(\.\.\.)?')
_INET = re.compile(r'sa_family=AF_INET6?, sin6?_port=htons\((\d+)\).*?'
                   r'(?:inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)")')
_UNIX = re.compile(r'sa_family=AF_UNIX, sun_path=(@?)"((?:[^"\\]|\\.)*)"')
_EXITED = re.compile(r"^\+\+\+ (exited with (\d+)|killed by (\w+)).* \+\+\+$")
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
SPAWNS = ("clone", "clone3", "fork", "vfork")
OPENS = ("open", "openat", "openat2", "creat")


def unescape(text: str) -> str:
    """strace's C-style escapes back to text."""
    try:
        raw = text.encode("latin-1", "backslashreplace").decode("unicode_escape")
        return raw.encode("latin-1", "replace").decode("utf-8", "replace")
    except UnicodeDecodeError:
        return text


@dataclass
class Process:
    pid: int
    parent: int | None
    cwd: str
    moved: bool = False  # called chdir itself
    execs: list[list[str]] = field(default_factory=list)  # argv of each successful execve
    paths: list[str] = field(default_factory=list)  # the program of each execve

    def command(self) -> str:
        return " ".join(self.execs[-1])[:300] if self.execs else "(no exec)"


@dataclass
class Open:
    pid: int
    path: str
    write: bool
    ok: bool


@dataclass
class Connect:
    pid: int
    call: str  # connect | sendto | sendmsg
    family: str  # inet | inet6 | unix
    address: str
    port: int | None
    ok: bool


@dataclass
class Trace:
    processes: dict[int, Process] = field(default_factory=dict)
    opens: list[Open] = field(default_factory=list)
    connects: list[Connect] = field(default_factory=list)
    first: int | None = None
    exit_status: int | None = None
    killed_by: str | None = None
    lines: int = 0
    unparsed: int = 0

    def ancestors(self, pid: int) -> list[int]:
        out, seen = [], set()
        parent = self.processes[pid].parent if pid in self.processes else None
        while parent is not None and parent not in seen:
            seen.add(parent)
            out.append(parent)
            parent = self.processes[parent].parent if parent in self.processes else None
        return out


def _process(trace: Trace, pid: int) -> Process:
    if pid not in trace.processes:
        trace.processes[pid] = Process(pid, None, "/")
        if trace.first is None:
            trace.first = pid
    return trace.processes[pid]


def _path(process: Process, value: str) -> str:
    return posixpath.normpath(posixpath.join(process.cwd, value))


def _argv(args: str, after: int) -> list[str]:
    """The strings of the `[...]` list that starts after position `after`."""
    pos = args.find("[", after)
    out: list[str] = []
    if pos < 0:
        return out
    pos += 1
    while pos < len(args):
        if args.startswith("]", pos):
            break
        match = _STRING.match(args, pos)
        if not match:
            break
        out.append(unescape(match.group(1)))
        pos = match.end()
        while pos < len(args) and args[pos] in ", ":
            pos += 1
    return out


def _record(trace: Trace, pid: int, name: str, args: str, result: str,
            error: str | None) -> None:
    process = _process(trace, pid)
    ok = result != "?" and not result.startswith("-")
    first = _STRING.search(args)
    string = unescape(first.group(1)) if first else None
    if name in SPAWNS and ok and int(result) > 0:
        child = _process(trace, int(result))
        child.parent = pid
        if not child.moved:  # its first lines can come before this one
            child.cwd = process.cwd
    elif name == "execve" and ok and first:
        process.paths.append(string)
        process.execs.append(_argv(args, first.end()))
    elif name == "chdir" and ok and string is not None:
        process.cwd = _path(process, string)
        process.moved = True
    elif name in OPENS and string is not None:
        if string.startswith("/") or name in ("open", "creat") or args.startswith("AT_FDCWD"):
            path = _path(process, string)
        else:
            path = f"(relative to an open folder) {string}"
        trace.opens.append(Open(pid, path,
                                name == "creat" or any(f in args for f in WRITE_FLAGS), ok))
    elif name in ("connect", "sendto", "sendmsg"):
        inet = _INET.search(args)
        if inet:
            family = "inet6" if inet.group(3) else "inet"
            trace.connects.append(Connect(pid, name, family, inet.group(2) or inet.group(3),
                                          int(inet.group(1)), ok or error == "EINPROGRESS"))
        else:
            unix = _UNIX.search(args)
            if unix and name == "connect":
                trace.connects.append(Connect(pid, name, "unix", unix.group(1) + unescape(
                    unix.group(2)), None, ok))


def parse(text: str) -> Trace:
    trace = Trace()
    pending: dict[int, str] = {}
    for line in text.splitlines():
        trace.lines += 1
        match = _LINE.match(line)
        if not match:
            trace.unparsed += 1
            continue
        pid, rest = int(match.group(1)), match.group(3)
        _process(trace, pid)
        exited = _EXITED.match(rest)
        if exited:
            if pid == trace.first:
                if exited.group(2) is not None:
                    trace.exit_status = int(exited.group(2))
                else:
                    trace.killed_by = exited.group(3)
            continue
        if rest.startswith("---"):
            continue  # a signal
        if rest.endswith("<unfinished ...>"):
            pending[pid] = rest[: -len("<unfinished ...>")].rstrip()
            continue
        resumed = _RESUMED.match(rest)
        if resumed:
            rest = pending.pop(pid, f"{resumed.group(1)}(") + resumed.group(2)
        call = _CALL.match(rest)
        if not call:
            trace.unparsed += 1
            continue
        _record(trace, pid, call.group(1), call.group(2), call.group(3), call.group(4))
    return trace

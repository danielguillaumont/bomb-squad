"""What the package did, from the trace and the sink, set against what the static scan
predicted. Observed with no static finding marks a gap in the static rules. Predicted but
not observed is not cleared: payloads can be time-gated or conditional."""

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass, field

from bombsquad.detonate.canary import HOME, Canaries, found_in
from bombsquad.detonate.trace import Trace

# The processes whose code is the package's: npm's `sh -c` for a lifecycle script, pip's
# build-backend helper (which runs setup.py or the build backend), and the import step.
IMPORT_STEP = "/opt/detonate/import.py"
BUILD_TOOLS = frozenset({"cc", "gcc", "g++", "c++", "cc1", "cc1plus", "as", "ld", "collect2",
                         "make", "cmake", "ninja", "cargo", "rustc", "git", "uname", "ldconfig",
                         "x86_64-linux-gnu-gcc", "aarch64-linux-gnu-gcc"})
PERSISTENCE = (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".bash_logout",
               ".ssh/", ".config/autostart/", ".config/systemd/", ".local/share/systemd/",
               ".npmrc", ".pypirc", ".gitconfig", ".git-credentials", ".aws/")
SYSTEM_PERSISTENCE = ("/etc/", "/var/spool/cron", "/usr/lib/systemd/", "/lib/systemd/")

# What each static rule predicts that a detonation could show.
PREDICTS = {
    "network": {"BS-NET-001", "BS-NET-002", "BS-NET-003", "BS-EX-001", "BS-GHA-006"},
    "credentials read": {"BS-CR-001", "BS-EX-001"},
    "credentials sent": {"BS-EX-001", "BS-GHA-006"},
    "programs started": {"BS-PRC-001", "BS-NET-002"},
    "persistence": {"BS-TS-001"},
}
CATEGORIES = tuple(PREDICTS)


@dataclass
class Observation:
    ecosystem: str
    exit_status: int | None
    killed_by: str | None
    timed_out: bool
    hook_commands: list[str] = field(default_factory=list)
    credentials_read: list[dict] = field(default_factory=list)
    credentials_sent: list[dict] = field(default_factory=list)
    programs_started: list[dict] = field(default_factory=list)
    build_tools: list[str] = field(default_factory=list)
    network: list[dict] = field(default_factory=list)
    dns_names: list[str] = field(default_factory=list)
    sink_connections: list[dict] = field(default_factory=list)
    persistence: list[dict] = field(default_factory=list)
    manager_network: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def seen(self) -> set[str]:
        return {name for name, present in (
            ("network", self.network or self.sink_connections),
            ("credentials read", self.credentials_read),
            ("credentials sent", self.credentials_sent),
            ("programs started", self.programs_started),
            ("persistence", self.persistence)) if present}

    def to_dict(self) -> dict:
        return asdict(self)


def _name(argv: list[str], path: str) -> str:
    return (argv[0] if argv else path).rsplit("/", 1)[-1]


def _hook_command(execs: list[list[str]]) -> str:
    for argv in execs:
        if len(argv) > 2 and argv[1] == "-c":
            return argv[2][:300]  # the lifecycle script as package.json has it
    return " ".join(execs[-1])[:300] if execs else "(no exec)"


def hook_roots(trace: Trace, ecosystem: str) -> tuple[set[int], int | None]:
    """The processes that start the package's own code, and npm's own process."""
    roots: set[int] = set()
    manager = None
    for pid, process in trace.processes.items():
        for argv, path in zip(process.execs, process.paths, strict=False):
            if ecosystem == "npm":
                if manager is None and (_name(argv, path) == "npm" or any(
                        a.endswith("npm-cli.js") for a in argv)):
                    manager = pid
                elif (_name(argv, path) == "sh" and len(argv) > 2 and argv[1] == "-c"
                      and manager is not None and manager in trace.ancestors(pid)):
                    roots.add(pid)
            elif any("_in_process" in a or a == IMPORT_STEP for a in argv):
                roots.add(pid)
    # Keep the outermost: a root below another root is that root's code.
    outer = {pid for pid in roots if not set(trace.ancestors(pid)) & roots}
    return outer, manager


def _decoded(event: dict) -> bytes:
    try:
        return base64.b64decode(event.get("data") or "")
    except (binascii.Error, ValueError):
        return b""


def observe(trace: Trace, sink_events: list[dict], canaries: Canaries, ecosystem: str,
            timed_out: bool = False) -> Observation:
    roots, manager = hook_roots(trace, ecosystem)
    package = {pid for pid in trace.processes
               if pid in roots or set(trace.ancestors(pid)) & roots}
    obs = Observation(ecosystem, trace.exit_status, trace.killed_by, timed_out)
    obs.hook_commands = [_hook_command(trace.processes[pid].execs) for pid in sorted(roots)]

    canary_paths = {path: name for name, path in zip(canaries.files, canaries.paths(),
                                                     strict=True)}
    seen_reads = set()
    for item in trace.opens:
        if item.path in canary_paths and (item.pid, item.path) not in seen_reads:
            expected = (ecosystem == "npm" and item.pid == manager
                        and canary_paths[item.path] == ".npmrc")
            if expected:
                continue
            seen_reads.add((item.pid, item.path))
            obs.credentials_read.append({
                "file": "~/" + canary_paths[item.path], "opened": item.ok,
                "command": trace.processes[item.pid].command(),
                "package_code": item.pid in package})
        if item.write and item.ok and item.pid in package:
            relative = item.path[len(HOME) + 1:] if item.path.startswith(HOME + "/") else None
            if (relative is not None and relative.startswith(PERSISTENCE)) or (
                    relative is None and item.path.startswith(SYSTEM_PERSISTENCE)):
                obs.persistence.append({"file": item.path,
                                        "command": trace.processes[item.pid].command()})

    first_child_exec = set()
    if ecosystem == "npm":
        for pid, process in trace.processes.items():
            if process.parent in roots and process.execs:
                first_child_exec.add(pid)
    for pid in sorted(package):
        process = trace.processes[pid]
        if pid in roots:
            continue
        for i, (argv, path) in enumerate(zip(process.execs, process.paths, strict=False)):
            if pid in first_child_exec and i == 0:
                continue  # the lifecycle script's own command, such as `node install.js`
            if _name(argv, path) in BUILD_TOOLS:
                obs.build_tools.append(_name(argv, path))
                continue
            obs.programs_started.append({"command": " ".join(argv)[:300], "program": path})
    obs.build_tools = sorted(set(obs.build_tools))

    for item in trace.connects:
        if item.family == "unix":
            continue
        record = {"call": item.call, "address": item.address, "port": item.port,
                  "command": trace.processes[item.pid].command()}
        (obs.network if item.pid in package else obs.manager_network).append(record)

    for event in sink_events:
        kind = event.get("kind")
        if kind == "dns" and event.get("name"):
            obs.dns_names.append(event["name"][:256])
            label_text = event["name"].replace(".", "").encode()
            for what in found_in(label_text, canaries.tokens):
                obs.credentials_sent.append({"secret": what, "via": "DNS name",
                                             "name": event["name"][:256]})
        elif kind == "tcp":
            data = _decoded(event)
            obs.sink_connections.append({"port": event.get("port"), "bytes": event.get("bytes"),
                                         "http": event.get("http"), "sni": event.get("sni")})
            for what in found_in(data, canaries.tokens):
                obs.credentials_sent.append({"secret": what, "via": f"TCP port {event.get('port')}",
                                             "host": (event.get("http") or {}).get("host")
                                             or event.get("sni")})
        elif kind == "truncated":
            obs.notes.append(f"The sink stopped recording after {event.get('after')} events.")
    obs.dns_names = sorted(set(obs.dns_names))
    if not roots:
        obs.notes.append("No install script, build step or import ran package code.")
    return obs


@dataclass
class Comparison:
    confirmed: list[str]  # predicted and observed
    gaps: list[str]  # observed with no static finding
    not_observed: list[str]  # predicted, not observed: not cleared

    def to_dict(self) -> dict:
        return asdict(self)


def compare(rule_ids: set[str], observation: Observation) -> Comparison:
    seen = observation.seen()
    predicted = {c for c in CATEGORIES if PREDICTS[c] & rule_ids}
    return Comparison(sorted(predicted & seen, key=CATEGORIES.index),
                      sorted(seen - predicted, key=CATEGORIES.index),
                      sorted(predicted - seen, key=CATEGORIES.index))

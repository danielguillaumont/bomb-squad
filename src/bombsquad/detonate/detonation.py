"""`bombsquad detonate`: fetch a release, scan it statically, run it in the sandbox, and
report what it did next to what the static scan predicted."""

from __future__ import annotations

import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from bombsquad.archive import unpack
from bombsquad.detonate import canary, observe, runner, trace
from bombsquad.model import Level
from bombsquad.registry import Fetch, download, http_get, npm_releases, pypi_releases
from bombsquad.scan import NOT_REACHED_IN_PACKAGE, NOT_RUN_FROM_PACKAGE, scan

LIMITS = [
    "Dependencies are not installed: the network reaches only the sink. Code that needs "
    "them fails when it loads them.",
    "TLS traffic is recorded by server name only; what it carries is not seen, so a secret "
    "sent over HTTPS shows as a read and a connection, not as sent.",
    "One run, with a time limit, as a fresh user on a fresh machine. Payloads gated on "
    "time, environment, host name or a later run are not seen.",
    "Reading environment variables leaves no trace; only a secret from them that is sent "
    "in the clear is seen.",
    "Something predicted but not observed is not cleared.",
]


@dataclass
class DetonationReport:
    subject: str
    artifact: str
    observation: observe.Observation
    comparison: observe.Comparison
    static_rules: list[str]
    limits: list[str] = field(default_factory=lambda: list(LIMITS))
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"subject": self.subject, "artifact": self.artifact,
                "observed": self.observation.to_dict(), "static_rules": self.static_rules,
                "comparison": self.comparison.to_dict(), "notes": self.notes,
                "limits": self.limits}


def parse_spec(spec: str) -> tuple[str, str, str]:
    """`npm:<name>@<version>` or `pypi:<name>@<version>`."""
    ecosystem, sep, rest = spec.partition(":")
    name, at, version = rest.rpartition("@")
    if not sep or ecosystem not in ("npm", "pypi") or not at or not name or not version:
        raise ValueError(f"expected npm:<name>@<version> or pypi:<name>@<version>, "
                         f"got {spec!r}")
    runner.check_name(ecosystem, name)
    return ecosystem, name, version


def fetch_artifact(ecosystem: str, name: str, version: str, fetch: Fetch = http_get
                   ) -> tuple[str, bytes]:
    """The npm tarball, or for PyPI the sdist (which runs setup.py or a build backend) and
    otherwise a wheel. Checked against the registry's hash."""
    lookup = npm_releases if ecosystem == "npm" else pypi_releases
    [release] = lookup(name, [version], fetch)
    if not release.artifacts:
        raise runner.DetonationError(f"{ecosystem}:{name}@{version} has no artifact")
    chosen = next((a for a in release.artifacts if a.kind == "sdist"), release.artifacts[0])
    return chosen.filename, download(chosen, fetch)


def static_rules(root: Path) -> list[str]:
    """Rule IDs of the static findings that installing the package runs."""
    report = scan([root], package=True)
    return sorted({f.rule.id for f in report.findings
                   if not (f.level is Level.INFO and any(
                       note in (NOT_RUN_FROM_PACKAGE, NOT_REACHED_IN_PACKAGE)
                       for note in f.limitations))})


def detonate(spec: str, artifact: Path | None = None, timeout: int = 120,
             fetch: Fetch = http_get, run_detonation=runner.run_detonation) -> DetonationReport:
    if not sys.platform.startswith("linux"):
        raise runner.DetonationError(
            "detonation runs only on a Linux host, such as a CI runner; nothing was run")
    ecosystem, name, version = parse_spec(spec)
    if artifact is not None:
        artifact_name, data = artifact.name, artifact.read_bytes()
    else:
        artifact_name, data = fetch_artifact(ecosystem, name, version, fetch)
    canaries = canary.make()
    with tempfile.TemporaryDirectory(prefix="bombsquad-detonate-") as tmp:
        root, skipped = unpack(data, artifact_name, Path(tmp) / "unpacked")
        rules = static_rules(root)
        result = run_detonation(ecosystem, name, version, artifact_name, data,
                                root if ecosystem == "npm" else None, canaries, timeout)
    parsed = trace.parse(result.trace)
    observation = observe.observe(parsed, result.sink_events, canaries, ecosystem,
                                  result.timed_out)
    observation.notes += result.notes
    notes = [f"{artifact_name}: {n}" for n in skipped]
    if parsed.unparsed:
        notes.append(f"{parsed.unparsed} of {parsed.lines} trace lines were not read.")
    return DetonationReport(f"{ecosystem}:{name}@{version}", artifact_name, observation,
                            observe.compare(set(rules), observation), rules, notes=notes)


def _items(title: str, rows: list[str]) -> list[str]:
    return [f"{title}:", *[f"  - {row}" for row in rows]] if rows else []


def render(report: DetonationReport) -> str:
    o, c = report.observation, report.comparison
    status = (f"killed by {o.killed_by}" if o.killed_by else
              f"exit status {o.exit_status}" if o.exit_status is not None else "no exit status")
    lines = [f"Detonated {report.subject} ({report.artifact}): {status}"
             + (", stopped at the time limit" if o.timed_out else ""), ""]
    lines += _items("Package code that ran", o.hook_commands)
    lines += _items("Fake credentials read", [
        f"{r['file']} by {r['command']}" + ("" if r["opened"] else " (open failed)")
        for r in o.credentials_read])
    lines += _items("Fake credentials sent", [
        f"{r['secret']} via {r['via']}" + (f" to {r['host']}" if r.get("host") else "")
        for r in o.credentials_sent])
    lines += _items("Network attempts", [
        f"{r['call']} {r['address']}:{r['port']} by {r['command']}" for r in o.network])
    lines += _items("DNS names asked for", o.dns_names)
    lines += _items("Programs started", [r["command"] for r in o.programs_started])
    lines += _items("Persistence", [f"{r['file']} by {r['command']}" for r in o.persistence])
    if o.build_tools:
        lines.append(f"Build tools run: {', '.join(o.build_tools)}")
    lines += ["", "Against the static scan (" + (", ".join(report.static_rules) or
                                                "no findings that installing runs") + "):"]
    lines += [f"  - confirmed: {', '.join(c.confirmed) or 'none'}",
              f"  - observed with no static finding (a gap in the rules): "
              f"{', '.join(c.gaps) or 'none'}",
              f"  - predicted, not observed (not cleared): {', '.join(c.not_observed) or 'none'}"]
    lines += [""] + _items("Notes", o.notes + report.notes)
    lines += _items("What this cannot see", report.limits)
    lines += ["", "Nothing observed does not mean safe."]
    return "\n".join(line for line in lines) + "\n"

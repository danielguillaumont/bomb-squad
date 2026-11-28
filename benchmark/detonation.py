"""Detonate a benchmark package in the sandbox and keep only what scoring needs.

Off unless `run --detonate` names the set. The sandbox is `bombsquad.detonate`: no host
mounts, fake credentials, and a network that reaches only the local sink. The row keeps
counts and categories, never DNS names, commands or sent bytes, which are sample content.
"""

from __future__ import annotations

import io
import re
import tarfile
import time
from pathlib import Path

from benchmark.samples import INNER_ARCHIVES
from bombsquad.detonate import canary, observe, runner, trace
from bombsquad.detonate.detonation import fetch_artifact, installed_fallback
from bombsquad.registry import Fetch

TIMEOUT_SECONDS = 60
# What a detonation counts as flagging: package code read or sent a fake credential, or
# wrote somewhere that persists. Network access alone is common in benign install scripts.
STRONG = ("credentials read", "credentials sent", "persistence")


def _safe(text: str) -> str:
    return re.sub(r"[^\w.+-]", "_", text).lstrip("._-") or "package"


def pack_sdist(root: Path, name: str, version: str) -> tuple[str, bytes]:
    """The unpacked folder as an sdist pip can install: `name-version/` at the top."""
    top = f"{_safe(name)}-{_safe(version)}"
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for path in sorted(root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                tar.add(path, arcname=f"{top}/{path.relative_to(root).as_posix()}",
                        recursive=False)
    return f"{top}.tar.gz", out.getvalue()


def sample_artifact(ecosystem: str, name: str, version: str, root: Path, work: Path
                    ) -> tuple[str, bytes]:
    """What to install for a dataset sample. npm installs from the unpacked folder, so the
    artifact is only copied in. PyPI installs the package archive the sample holds, when it
    holds exactly one, and otherwise the folder packed as an sdist."""
    if ecosystem == "npm":
        return f"{_safe(name)}-{_safe(version)}.tgz", b""
    inner = [p for p in sorted((work / "sample").rglob("*")) if p.is_file()
             and p.name.lower().endswith(INNER_ARCHIVES) and runner.FILENAME.match(p.name)]
    if len(inner) == 1 and inner[0].name.lower().endswith((".tar.gz", ".whl", ".zip")):
        return inner[0].name, inner[0].read_bytes()
    return pack_sdist(root, name, version)


def summarise(obs: observe.Observation, static_rules: set[str]) -> dict:
    seen = obs.seen()
    comparison = observe.compare(static_rules, obs)
    return {
        "seen": sorted(seen, key=observe.CATEGORIES.index),
        "flagged": bool(seen & set(STRONG)),
        "hooks": len(obs.hook_commands),
        "credentials_read": sum(1 for r in obs.credentials_read if r["package_code"]),
        "credentials_sent": sorted({r["secret"] for r in obs.credentials_sent}),
        "programs": len(obs.programs_started),
        "network": len(obs.network),
        "dns_names": len(obs.dns_names),
        "persistence": len(obs.persistence),
        "gaps": comparison.gaps,
        "exit_status": obs.exit_status,
        "timed_out": obs.timed_out,
    }


def detonate(row: dict, root: Path, work: Path, from_registry: bool, fetch: Fetch,
             timeout: int = TIMEOUT_SECONDS, run=runner.run_detonation) -> dict:
    """Detonate one package; `from_registry` for benign releases, fetched again as the
    registry serves them, and otherwise the dataset sample unpacked at `root`."""
    start = time.monotonic()
    result: dict = {}
    try:
        ecosystem, name, version = row["ecosystem"], row["name"], row["version"]
        runner.check_name(ecosystem, name)
        fallback = None
        if from_registry:
            artifact_name, data, fallback = fetch_artifact(ecosystem, name, version, fetch)
        else:
            artifact_name, data = sample_artifact(ecosystem, name, version, root, work)
        secrets = canary.make()
        ran = run(ecosystem, name, version, artifact_name, data,
                  root if ecosystem == "npm" else None, secrets, timeout, fallback=fallback)
        parsed = trace.parse(ran.trace)
        obs = observe.observe(parsed, ran.sink_events, secrets, ecosystem, ran.timed_out)
        static = set((row.get("bombsquad") or {}).get("rules") or [])
        result = summarise(obs, static)
        result["wheel_instead"] = installed_fallback(parsed, fallback[0] if fallback
                                                     else None)
        result["error"] = None
    except Exception as exc:  # a package that cannot be detonated is reported, not fatal
        result = {"error": f"{exc.__class__.__name__}: {str(exc)[:300]}"}
    result["seconds"] = round(time.monotonic() - start, 2)
    return result

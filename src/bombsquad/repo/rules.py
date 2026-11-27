"""Rules for repository configuration: GitHub Actions workflows, editor and container
start-up commands, and pinned third-party code.

The workflow rules are deliberately narrow: each one is a trust-boundary case that leads
to code execution or credential exposure. zizmor is the reference for a full audit.
"""

from bombsquad.model import Level, Rule

_PUBLIC = ("Whether the repository is public is not known to the scan.",)

RULES: dict[str, Rule] = {r.id: r for r in (
    Rule(
        "BS-GHA-001", "workflow", "Checks out pull-request code in a privileged workflow",
        Level.HIGH,
        "The workflow runs on pull_request_target, workflow_run or issue_comment, which run "
        "with the base repository's secrets and a token that can write, and it checks out "
        "code from the pull request. Any build, install or test step that follows runs "
        "code the pull request's author wrote.",
        "Use the pull_request event for untrusted code, or keep the checkout away from "
        "every step that has secrets or write access.",
        ("Whether later steps run code from the checkout is not checked; even `npm install` "
         "does.",),
    ),
    Rule(
        "BS-GHA-002", "workflow", "Expands attacker-controlled text into a script", Level.HIGH,
        "A ${{ }} expression is replaced with its value before the script runs, so text "
        "such as an issue title or branch name becomes part of the script. Someone who "
        "controls that text can run commands in the workflow.",
        "Pass the value through an env: variable and quote it in the script.",
        ("Values that reach the script through env, step outputs or files are not "
         "followed.", "Workflow inputs are not reported."),
    ),
    Rule(
        "BS-GHA-003", "workflow", "Leaves the workflow token's permissions broad",
        Level.REVIEW,
        "The GITHUB_TOKEN is granted write-all, or no permissions block limits it, in which "
        "case it gets the repository's default, which can be read and write. Any step that "
        "is compromised can then push code, create releases or change settings.",
        "Add a permissions block that grants only what each job needs.",
        ("The repository's default token setting is not known to the scan.",),
    ),
    Rule(
        "BS-GHA-004", "workflow", "Can request cloud identity tokens", Level.REVIEW,
        "id-token: write lets the job mint OpenID Connect tokens, which cloud providers "
        "and package registries exchange for credentials. Any step in the job can request "
        "one.",
        "Grant id-token: write only to the job that deploys or publishes, and check which "
        "cloud roles trust this repository.",
    ),
    Rule(
        "BS-GHA-005", "workflow", "Runs on a self-hosted runner", Level.REVIEW,
        "Self-hosted runners keep state between jobs and sit on the owner's network. On a "
        "public repository, pull requests from forks can run code on them, subject to the "
        "repository's approval settings.",
        "Use GitHub-hosted runners for untrusted code, or ephemeral, isolated self-hosted "
        "runners.",
        (*_PUBLIC, "Only the literal self-hosted label is recognised."),
    ),
    Rule(
        "BS-GHA-006", "exfiltration", "Sends secrets to the network from a step", Level.HIGH,
        "A run step both uses repository secrets and talks to the network. Sending every "
        "secret, the whole environment, or a secret in a request body or URL query is the "
        "shape of the GhostAction workflows. Deploy steps also send tokens, usually in an "
        "authorization header, which is reported for review.",
        "Check the destination host and why the secret goes there.",
        ("Only the step's own bash or sh script is checked, not files it runs or other "
         "shells.",),
    ),
    Rule(
        "BS-PIN-001", "pinning", "Runs third-party code from a tag or branch", Level.REVIEW,
        "The code is fetched by a tag or branch name, which its owner, or anyone who takes "
        "over the owner's account, can point at different code at any time. Pinning to a "
        "full commit SHA fixes what runs.",
        "Pin to a full commit SHA and keep the tag in a comment for updates.",
        ("Actions owned by actions/ and github/ are not reported.",
         "A SHA pin does not prove the commit belongs to the named repository's history."),
    ),
    Rule(
        "BS-EP-002", "auto-execution", "Runs a task when the folder is opened", Level.REVIEW,
        "VS Code and editors built on it run this task as soon as the folder is opened, "
        "once the workspace is trusted and automatic tasks are allowed. Repository-poisoning "
        "campaigns plant exactly this.",
        "Check what the task runs before trusting the folder.",
    ),
    Rule(
        "BS-EP-003", "auto-execution", "Runs a command on the host before a dev container "
                                       "starts",
        Level.REVIEW,
        "initializeCommand runs on the local machine, outside the container, whenever the "
        "dev container is created or started, so it can read the developer's files and "
        "credentials.",
        "Check what the command runs; most dev containers do not need one.",
    ),
)}

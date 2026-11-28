"""Rules for repository configuration: GitHub Actions workflows, editor and container
start-up commands, agent instructions and configurations, and pinned third-party code.

The workflow rules are deliberately narrow: each one is a trust-boundary case that leads
to code execution or credential exposure. zizmor is the reference for a full audit.
"""

from bombsquad.model import Level, Rule

_PUBLIC = ("Whether the repository is public is not known to the scan.",)
_INSTRUCTIONS = ("Instructions are matched line by line against fixed phrasings; reworded, "
                 "translated or split instructions are missed, and quoted examples are "
                 "reported.",)

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
        (*_PUBLIC, "Recognised by the self-hosted label, or an expression that names it. A "
                   "runner group, or a custom label alone, is not recognised."),
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
    Rule(
        "BS-AG-001", "agent", "Tells the agent to act without confirmation", Level.REVIEW,
        "Agent instructions or flags tell the agent to skip confirmation or permission "
        "prompts, so the commands and edits that follow are not shown to anyone first. "
        "Instruction-file poisoning relies on this.",
        "Check which actions the instruction covers, and keep confirmation for commands, "
        "network access and file writes outside the project.",
        _INSTRUCTIONS,
    ),
    Rule(
        "BS-AG-002", "agent", "Tells the agent to hide what it does or ignore its other "
                              "instructions",
        Level.HIGH,
        "Agent instructions tell the agent to keep actions from the user or to set aside "
        "its other instructions. Legitimate project instructions rarely need either.",
        "Remove the instruction and review what else the file asks the agent to do.",
        _INSTRUCTIONS,
    ),
    Rule(
        "BS-AG-003", "credentials", "Tells the agent to read credentials", Level.REVIEW,
        "Agent instructions ask the agent to read, print or send a credential file or "
        "token variable, such as ~/.aws/credentials or GITHUB_TOKEN. An agent that follows "
        "them puts the secret into its context and its output.",
        "Confirm why the agent needs the credential; agents rarely do.",
        _INSTRUCTIONS,
    ),
    Rule(
        "BS-AG-004", "network", "Tells the agent to fetch from or send to a URL",
        Level.REVIEW,
        "Agent instructions tell the agent to fetch, run or follow content from a URL, or to "
        "send something to one. Whoever controls that page can change what the agent is told "
        "to do at any time, and whatever is sent leaves the machine.",
        "Check the URL. Copy what the agent needs into the repository instead of linking "
        "it.",
        _INSTRUCTIONS,
    ),
    Rule(
        "BS-AG-005", "auto-execution", "Runs a command on agent events", Level.REVIEW,
        "An agent configuration runs a shell command on its own: a hook on session start, "
        "prompts or tool calls, a status line, a credential helper, or a command expanded "
        "when a slash command or skill is used. Worms such as ChainDrop plant agent settings "
        "for this.",
        "Check what the command runs before opening the project with the agent.",
        ("Hooks in user-level settings outside the repository are not seen.",),
    ),
    Rule(
        "BS-AG-006", "agent", "Approves agent or task actions in advance", Level.REVIEW,
        "A setting approves tool calls, shell commands, MCP servers or automatic tasks before "
        "anyone sees them, such as bypassPermissions, an allow rule for every shell command, "
        "enableAllProjectMcpServers or chat.tools.autoApprove. Instructions planted in the "
        "repository then run without a prompt.",
        "Remove the setting from the repository; each person can approve what they trust.",
        ("Settings outside the repository, which can override these, are not seen.",),
    ),
    Rule(
        "BS-AG-007", "network", "Redirects the agent's network traffic", Level.REVIEW,
        "A variable sends the agent's or its tools' API traffic to another host, or turns "
        "off TLS certificate checks. Requests to a model API carry the API key and the "
        "conversation, including code and anything the agent has read.",
        "Check who runs the host; a proxy belongs in each person's own settings.",
    ),
    Rule(
        "BS-AG-008", "auto-execution", "Makes programs load code through an environment "
                                       "variable",
        Level.HIGH,
        "A variable such as NODE_OPTIONS=--require, BASH_ENV, LD_PRELOAD or PERL5OPT makes "
        "every program of that kind load extra code at start, including the agent, MCP "
        "servers and every tool they run.",
        "Remove the variable, and review the code it loads.",
    ),
    Rule(
        "BS-MCP-001", "pinning", "Launches an MCP server package without a pinned version",
        Level.REVIEW,
        "npx, uvx and similar launchers fetch the newest matching release each time the "
        "agent starts the server, so a hijacked or typo-squatted release runs as soon as it "
        "is published. A container image without a digest has the same problem.",
        "Pin an exact version (pkg@1.2.3, pkg==1.2.3) or an image digest.",
        ("An exact version can still be republished on registries that allow it; npm and "
         "PyPI do not.",),
    ),
    Rule(
        "BS-MCP-002", "pinning", "Launches an archived reference MCP server", Level.REVIEW,
        "The server is one of the reference MCP servers that modelcontextprotocol moved to "
        "its archived repository (github.com/modelcontextprotocol/servers-archived). Archived "
        "servers receive no security fixes.",
        "Replace it with a maintained server for the same service.",
    ),
)}

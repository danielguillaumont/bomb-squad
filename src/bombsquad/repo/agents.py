"""AI coding agents: the instruction files they read, and the hooks, MCP servers, settings
and environment files they apply when they start in a project.

Instruction files are text an agent reads as orders. They are checked for phrasings that
skip confirmation, hide actions, read credentials or pull instructions from the web, and
the code in them is analysed like any other entry point's. Configurations are read for the
commands they run on their own and for what they approve in advance.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from bombsquad.code.common import CodeHit, Snippet, clip, credential_reference
from bombsquad.code.shell import split_command
from bombsquad.discovery import (
    Discovery,
    Target,
    find_targets,
    program_name,
    shell_join,
    target_path,
)
from bombsquad.model import EntryPoint, Level, Region
from bombsquad.repo import jsonc, markdown
from bombsquad.repo import yamltree as y
from bombsquad.sources import InputError, read_source
from bombsquad.textpos import Positions

AGENT_DIRS = frozenset({".claude", ".cursor", ".github", ".gemini", ".codex", ".vscode", ".kiro",
                        ".windsurf", ".clinerules", ".roo", ".junie", ".amazonq", ".agents"})
PLUGIN_DIR = ".claude-plugin"
MAX_IMPORT_DEPTH = 5  # Claude Code follows @imports five levels deep
TRUSTED = ", once the folder is trusted"


@dataclass(frozen=True)
class AgentFile:
    kind: str  # instructions | claude | mcp | gemini | cursor-hooks | codex | vscode | env
    label: str  # what the file is, for the entry point
    tool: str
    trigger: str
    root: Path  # the project the agent works in


def _root(path: Path) -> Path:
    """The project folder: the parent of the agent folder the file sits in."""
    for parent in list(path.parents)[:6]:
        if parent.name.lower() in AGENT_DIRS:
            return parent.parent
    return path.parent


def _plugin(path: Path) -> bool:
    return (path.parent.parent / PLUGIN_DIR).is_dir()


def classify(path: Path) -> AgentFile | None:
    """Which agent file this is, from its name and where it sits."""
    name = path.name.lower()
    up = [p.name.lower() for p in list(path.parents)[:6]]
    parent = up[0] if up else ""
    suffix = path.suffix.lower()
    root = _root(path)

    def inst(label: str, tool: str, trigger: str) -> AgentFile:
        return AgentFile("instructions", label, tool, trigger, root)

    if name == "agents.md":
        return inst("AGENTS.md", "agents", "every session of an agent that reads AGENTS.md, "
                    "such as Codex, Cursor or GitHub Copilot, in this folder")
    if name in ("claude.md", "claude.local.md"):
        return inst(path.name, "Claude Code", "every Claude Code session in this folder")
    if name == "gemini.md":
        return inst(path.name, "Gemini CLI", "every Gemini CLI session in this folder")
    if name == "skill.md":
        skill = path.parent.name
        return inst(f"skill '{skill}'", "Claude Code" if ".claude" in up else "agents",
                    f"an agent using the {skill} skill, which it can choose to do on its own")
    if name == ".cursorrules":
        return inst(path.name, "Cursor", "every Cursor chat in this folder")
    if name == ".windsurfrules":
        return inst(path.name, "Windsurf", "every Windsurf chat in this folder")
    if name == ".clinerules" or parent == ".clinerules" and suffix == ".md":
        return inst("Cline rules", "Cline", "every Cline task in this folder")
    if parent == ".github" and name == "copilot-instructions.md":
        return inst(path.name, "GitHub Copilot", "GitHub Copilot chat and the Copilot coding "
                    "agent in this repository")
    if ".github" in up:
        if name.endswith(".instructions.md") and "instructions" in up:
            return inst("Copilot instructions", "GitHub Copilot",
                        "GitHub Copilot requests for the files the instructions apply to")
        if name.endswith(".prompt.md") and parent == "prompts":
            prompt = path.name[:-len(".prompt.md")]
            return inst(f"Copilot prompt /{prompt}", "GitHub Copilot",
                        f"the /{prompt} prompt in GitHub Copilot chat")
        if name.endswith(".agent.md") and parent == "agents":
            agent = path.name[:-len(".agent.md")]
            return inst(f"Copilot agent '{agent}'", "GitHub Copilot",
                        f"the {agent} custom agent in GitHub Copilot")
    if suffix in (".md", ".mdc"):
        if ".cursor" in up and "rules" in up:
            return inst("Cursor rule", "Cursor", "Cursor chats the rule applies to")
        if ".windsurf" in up and "rules" in up:
            return inst("Windsurf rule", "Windsurf", "Windsurf chats the rule applies to")
        if ".roo" in up and any(a.startswith("rules") for a in up):
            return inst("Roo Code rule", "Roo Code", "every Roo Code task in this folder")
        if ".kiro" in up and "steering" in up:
            return inst("Kiro steering file", "Kiro", "Kiro sessions the file applies to")
        if parent == ".junie" and name == "guidelines.md":
            return inst(path.name, "Junie", "every Junie task in this project")
        claude = ".claude" in up
        if (claude and "commands" in up) or parent == "commands" and _plugin(path):
            return inst(f"Claude Code command /{path.stem}", "Claude Code",
                        f"the /{path.stem} command in Claude Code")
        if (claude and "agents" in up) or parent == "agents" and _plugin(path):
            return inst(f"Claude Code subagent '{path.stem}'", "Claude Code",
                        f"Claude Code handing work to the {path.stem} subagent, which it can "
                        "do on its own")
        if claude and "rules" in up:
            return inst("Claude Code rule", "Claude Code",
                        "every Claude Code session in this project")
        return None

    if parent == ".claude" and name in ("settings.json", "settings.local.json"):
        return AgentFile("claude", path.name, "Claude Code", "Claude Code in this project" +
                         TRUSTED, root)
    if name == "hooks.json" and parent == "hooks" and _plugin(path):
        return AgentFile("claude", "plugin hooks", "Claude Code",
                         "Claude Code, once the plugin is installed and enabled",
                         path.parent.parent)
    if name == ".mcp.json":
        plugin = (path.parent / PLUGIN_DIR).is_dir()
        return AgentFile("mcp", path.name, "Claude Code", "Claude Code start, once the plugin "
                         "is enabled" if plugin else "Claude Code start in this project, once "
                         "the server is approved", path.parent)
    if name == "mcp.json":
        tools = {".cursor": ("Cursor", "Cursor start in this project, once the server is "
                             "enabled"),
                 ".vscode": ("VS Code", "VS Code starting the server for chat, which it can do "
                             "automatically"),
                 ".amazonq": ("Amazon Q", "Amazon Q Developer start in this project"),
                 ".roo": ("Roo Code", "Roo Code start in this project")}
        if parent in tools:
            return AgentFile("mcp", f"{parent}/mcp.json", *tools[parent], root)
        if parent == "settings" and up[1:2] == [".kiro"]:
            return AgentFile("mcp", ".kiro/settings/mcp.json", "Kiro",
                             "Kiro start in this project", root)
        return None
    if name == "claude_desktop_config.json":
        return AgentFile("mcp", path.name, "Claude Desktop", "Claude Desktop start",
                         path.parent)
    if name in ("opencode.json", "opencode.jsonc"):
        return AgentFile("mcp", path.name, "opencode", "opencode start in this project",
                         path.parent)
    if parent == ".gemini" and name == "settings.json":
        return AgentFile("gemini", ".gemini/settings.json", "Gemini CLI",
                         "Gemini CLI start in this folder" + TRUSTED, root)
    if parent == ".cursor" and name == "hooks.json":
        return AgentFile("cursor-hooks", ".cursor/hooks.json", "Cursor",
                         "Cursor in this project", root)
    if parent == ".codex" and name == "config.toml":
        return AgentFile("codex", ".codex/config.toml", "Codex",
                         "Codex start in this project, once the project is trusted", root)
    if parent == ".vscode" and name == "settings.json":
        return AgentFile("vscode", ".vscode/settings.json", "VS Code",
                         "opening the folder in VS Code", root)
    if name == ".env":
        return AgentFile("env", path.name, "", "Gemini CLI and dotenv-based tools, which load "
                         ".env files from the project folder", path.parent)
    return None


def discover(path: Path, shown: str, text: str, found: Discovery, display) -> None:
    info = classify(path)
    if info is None:
        return
    if info.kind == "instructions":
        _Instructions(path, shown, text, found, display, info).run()
    elif info.kind == "env":
        _env_file(path, shown, text, found, info)
    elif info.kind == "codex":
        _Config(path, shown, text, found, display, info).codex()
    else:
        config = _Config(path, shown, text, found, display, info)
        root = config.read()
        if root is not None:
            config.dispatch(root)


# Instruction text --------------------------------------------------------------------------

_BOUNDARY = re.compile(r"[.!?;:](?=\s|$)")
_NEGATOR = re.compile(r"\b(?:never|not|no|without|skip(?:ping)?|bypass(?:ing)?|avoid|disable|"
                      r"turn\s+off)\b|n['’]t\b", re.IGNORECASE)
_ASK = (r"(?:ask(?:ing)?(?:\s+(?:the|a|any|users?|me|anyone|for)){0,4}\s+(?:confirmation|"
        r"permission|approval|consent)\b|ask(?:ing)?\s+(?:first|before)\b|asking\b|"
        r"confirm(?:ation|ing)?\b|approv(?:al|ing)\b|(?:permission|approval|confirmation|"
        r"safety)\s+(?:prompts?|checks?|dialogs?|steps?)\b)")
_PEOPLE = r"(?:the\s+)?(?:users?|human|developers?|operators?|reviewers?|maintainers?)"
# (rule, pattern, whether the phrasing carries a negation). "Don't ask for confirmation"
# is one negation; "never push without asking" is two, which is a safety rule, not a
# bypass, and "never ignore previous instructions" negates the instruction.
_PHRASES: tuple[tuple[str, re.Pattern, bool], ...] = (
    ("BS-AG-001", re.compile(
        rf"\b(?:without|no\s+need\s+(?:to|for)|never|don['’]?t|do\s+not|skip(?:ping)?|"
        rf"bypass(?:ing)?|disable|turn\s+off)\s+(?:[\w'’]+\s+){{0,3}}?{_ASK}",
        re.IGNORECASE), True),
    ("BS-AG-001", re.compile(
        r"--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b|"
        r"--yolo\b|\byolo\s+mode\b|--full-auto\b|--trust-all-tools\b|--allow-all-tools\b|"
        r"\bbypassPermissions\b|--approval-mode[= ]yolo\b", re.IGNORECASE), False),
    ("BS-AG-002", re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|"
        r"your\s+)?(?:previous|prior|above|earlier|other|system|safety|original|existing)\s+"
        r"(?:instructions|rules|prompts?|guidelines|guardrails|messages|directions)\b",
        re.IGNORECASE), False),
    ("BS-AG-002", re.compile(
        rf"\b(?:do\s+not|don['’]?t|never|without)\s+(?:tell(?:ing)?|inform(?:ing)?|"
        rf"mention(?:ing)?|notify(?:ing)?|alert(?:ing)?)\s+(?:this\s+|it\s+|anything\s+)?"
        rf"(?:to\s+)?{_PEOPLE}\b(?!['’])(?!\s+to\b)", re.IGNORECASE), True),
    ("BS-AG-002", re.compile(
        rf"\bwithout\s+{_PEOPLE}\s+(?:knowing|noticing|seeing)\b", re.IGNORECASE), True),
    ("BS-AG-002", re.compile(
        rf"\b(?:hide|conceal)\s+(?:this|it|these|that|the\s+\w+|your\s+\w+)\s+(?:\w+\s+)?"
        rf"from\s+{_PEOPLE}\b|\bkeep\s+(?:this|it|these|that)\s+(?:a\s+)?secret\s+from\b",
        re.IGNORECASE), False),
)
_READ_VERB = re.compile(r"\b(?:read|cat|open|print|output|echo|show|display|copy|upload|send|"
                        r"post|include|collect|attach|paste|share|dump|encode|exfiltrate|grab|"
                        r"retrieve|extract)\b", re.IGNORECASE)
_FETCH_VERB = re.compile(r"\b(?:fetch|download|curl|wget|retrieve|load|follow|obey|execute|"
                         r"run|install|import|pull|send|post|upload|submit)\b", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s<>()\[\]'\"`]+", re.IGNORECASE)
_LOCAL_HOST = re.compile(r"^https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|"
                         r"[\w.-]+\.localhost)(?:[:/]|$)", re.IGNORECASE)
_BANG = re.compile(r"!`([^`\n]+)`")  # Claude Code runs !`command` when a command is used
_IMPORT = re.compile(r"(?<![\w`/@])@((?:~/|\.{1,2}/|/)?[\w.-]+(?:/[\w.-]+)*\.[A-Za-z]\w*)")
_BROAD_SHELL = re.compile(r"^\s*(?:Bash|Shell|PowerShell)\s*(?:\(\s*(?:\*|:\*|\*\*|\*:\*)?\s*\))?"
                          r"\s*$")

SHELL_INFOS = frozenset({"", "sh", "bash", "shell", "zsh", "ksh", "dash", "console", "terminal",
                         "shellsession", "shell-session", "sh-session"})
CODE_INFOS = {**dict.fromkeys(SHELL_INFOS, "shell"),
              **dict.fromkeys(("powershell", "pwsh", "ps1", "ps", "posh"), "powershell"),
              **dict.fromkeys(("python", "py", "python3"), "python"),
              **dict.fromkeys(("js", "javascript", "node", "mjs", "cjs", "ts", "typescript",
                               "jsx", "tsx"), "javascript")}
_PROMPT = re.compile(r"^(\s*)[$%] ")


def _tag_text(line: str) -> str:
    """ASCII hidden as Unicode tag characters, which render as nothing."""
    return "".join(chr(ord(c) - 0xE0000) for c in line if 0xE0020 <= ord(c) <= 0xE007E)


def _clauses(line: str) -> list[tuple[int, int]]:
    out, start = [], 0
    for match in _BOUNDARY.finditer(line):
        out.append((start, match.start()))
        start = match.end()
    out.append((start, len(line)))
    return [(a, b) for a, b in out if line[a:b].strip()]


def _odd(text: str) -> bool:
    return len(_NEGATOR.findall(text)) % 2 == 1


def instruction_hits(line: str) -> list[tuple[str, int, int, str]]:
    """(rule, start, end, what) for each instruction phrasing in one line of text."""
    hits: list[tuple[str, int, int, str]] = []
    for a, b in _clauses(line):
        clause = line[a:b]
        for rule, pattern, negated in _PHRASES:
            for match in pattern.finditer(clause):
                # A phrasing that carries its own negation counts with it; any other only
                # counts when what comes before it in the clause does not negate it.
                if (_odd(clause[:match.end()]) if negated else not _odd(
                        clause[:match.start()])):
                    hits.append((rule, a + match.start(), a + match.end(),
                                 " ".join(match.group().split())))
        if _odd(clause):
            continue  # "never read ~/.ssh" is the opposite of an instruction to read it
        reference = credential_reference(clause)
        verb = _READ_VERB.search(clause)
        if reference and verb:
            hits.append(("BS-AG-003", a + verb.start(), b, f"{verb.group().lower()} … "
                         f"{reference}"))
        verb = _FETCH_VERB.search(clause)
        if verb:
            for url in _URL.finditer(clause):
                if not _LOCAL_HOST.match(url.group()):
                    hits.append(("BS-AG-004", a + url.start(), a + url.end(),
                                 f"{verb.group().lower()} {url.group()}"))
                    break
    return hits


class _Instructions:
    def __init__(self, path: Path, shown: str, text: str, found: Discovery, display,
                 info: AgentFile, entry: EntryPoint | None = None, via: str | None = None,
                 seen: set[Path] | None = None, depth: int = 0) -> None:
        self.path, self.shown, self.text, self.found, self.display, self.info = (
            path, shown, text, found, display, info)
        self.positions = Positions(text)
        self.doc = markdown.parse(text)
        self.via = via
        self.seen = seen if seen is not None else {path.resolve()}
        self.depth = depth
        self.entry = entry or EntryPoint(
            "agent", f"{info.label} (agent instructions)", info.trigger, shown,
            self.positions.line_region(1), f"instructions read by {info.tool}")
        self.bang = info.label.startswith(("Claude Code command", "skill"))

    def run(self) -> None:
        if self.depth == 0:
            self.found.entry_points.append(self.entry)
        for line in self.doc.prose:
            self.prose(line)
        for fence in self.doc.fences:
            self.fence(fence)
        if self.doc.front_matter is not None:
            self.front_matter(self.doc.front_matter)
        if self.info.tool in ("Claude Code", "Gemini CLI") and self.info.label.lower() in (
                "claude.md", "claude.local.md", "gemini.md"):
            self.imports()

    def hit(self, rule: str, start: int, end: int, evidence: str, via: list[str],
            level: Level | None = None) -> None:
        if self.via:
            via = [self.via, *via]
        self.found.hits.append((self.shown, CodeHit(
            rule, self.positions.region(start, end), clip(evidence), via, level=level),
            self.entry))

    def prose(self, line: int) -> None:
        start, text = self.doc.lines[line - 1]
        spans = self.doc.inline_code(line)
        # Inline code with a space in it is analysed as a command below; keep its URLs
        # out of the instruction check so a command is not reported twice.
        masked = text
        for span in spans:
            if " " in span.text and "://" in span.text:
                offset = span.start - start
                masked = masked[:offset] + " " * len(span.text) + masked[offset + len(
                    span.text):]
        for rule, a, b, what in instruction_hits(masked):
            via = [f'matched "{what}"']
            level = None
            if self.doc.in_comment(start + a):
                via.append("inside an HTML comment, which rendered Markdown does not show")
                level = Level.HIGH
            self.hit(rule, start + a, start + b, text.strip(), via, level)
        hidden = _tag_text(text)
        if hidden:
            for rule, _a, _b, what in instruction_hits(hidden):
                self.hit(rule, start, start + len(text), hidden,
                         [f'matched "{what}"', "hidden as Unicode tag characters, "
                          "which do not display"], Level.HIGH)
        for span in spans:
            index = span.start - start
            if self.bang and index > 0 and text[index - 1] == "!":
                continue
            if " " in span.text.strip():
                self.code("shell", span.text, span.start, f"inline code at line {line}")
        if self.bang:
            for match in _BANG.finditer(text):
                command = match.group(1)
                where = start + match.start(1)
                self.hit("BS-AG-005", start + match.start(), start + match.end(),
                         match.group(), [f"runs when {self.info.trigger}"])
                self.code("shell", command, where, f"!`command` at line {line}")

    def fence(self, fence: markdown.Fence) -> None:
        language = CODE_INFOS.get(fence.info)
        if language is None:
            return
        body = fence.body.replace("\r", " ")
        if language == "shell":
            body = _drop_output(body)
        self.code(language, body, fence.start, f"{fence.info or 'code'} block at line "
                                               f"{fence.line}")

    def code(self, language: str, code: str, index: int, origin: str) -> None:
        region = self.positions.region(index, index)
        anchor = self.positions.line_region(region.line)
        offset = (region.line - 1, region.column - 1)
        origin = f"{origin} in {self.info.label}"
        self.found.snippets.append((self.shown, Snippet(language, code, anchor, origin,
                                                        offset), self.entry))
        if language == "shell":
            for base in {self.info.root, self.path.parent}:
                find_targets(self.found, self.entry, code, base, self.display)

    def front_matter(self, span: markdown.Span) -> None:
        try:
            node = y.compose(span.text)
        except y.YamlError:
            return
        tools = y.get(node, "allowed-tools") or y.get(node, "tools")
        if tools is None:
            return
        values = [t for value in (y.strings(tools) or [y.text(tools) or ""])
                  for t in re.split(r",\s*|\s+(?=\w+\()", value) if t]
        for value in values:
            if _BROAD_SHELL.match(value):
                index = span.start + tools.start_mark.index
                self.hit("BS-AG-006", index, span.start + tools.end_mark.index,
                         self.positions.line_text(self.positions.region(index, index).line
                                                  ).strip(),
                         [f"allows every {value.split('(')[0].strip()} command without asking"])
                return

    def imports(self) -> None:
        """`@path` lines pull other files into the instructions."""
        if self.depth >= MAX_IMPORT_DEPTH:
            return
        for line in self.doc.prose:
            start, text = self.doc.lines[line - 1]
            masked = text
            for span in self.doc.inline_code(line):
                offset = span.start - start
                masked = masked[:offset] + " " * len(span.text) + masked[offset + len(
                    span.text):]
            for match in _IMPORT.finditer(masked):
                relative = match.group(1)
                if relative.startswith("~"):
                    continue  # outside the project
                target = (self.path.parent / relative).resolve()
                try:
                    target.relative_to(self.info.root.resolve())
                except ValueError:
                    continue
                if target in self.seen or not target.is_file():
                    continue
                self.seen.add(target)
                try:
                    imported = read_source(target)[0]
                except (InputError, OSError):
                    continue
                shown = self.display(target)
                if shown not in self.entry.targets:
                    self.entry.targets.append(shown)
                _Instructions(target, shown, imported, self.found, self.display, self.info,
                              self.entry, f"imported into {self.shown} with @{relative}",
                              self.seen, self.depth + 1).run()


def _drop_output(body: str) -> str:
    """In a terminal session (`$ command` lines), keep the commands and drop the output."""
    lines = body.split("\n")
    if not any(_PROMPT.match(line) for line in lines):
        return body
    out, continued = [], False
    for line in lines:
        if _PROMPT.match(line):
            match = _PROMPT.match(line)
            line = match.group(1) + "  " + line[match.end():]
            out.append(line)
        elif continued:
            out.append(line)
        else:
            out.append("")
        continued = bool(out[-1]) and out[-1].rstrip().endswith("\\")
    return "\n".join(out)


# Launchers and environment -----------------------------------------------------------------

DEPRECATED_NPM = frozenset(f"@modelcontextprotocol/server-{name}" for name in (
    "aws-kb-retrieval", "brave-search", "everart", "gdrive", "github", "gitlab", "google-maps",
    "postgres", "puppeteer", "redis", "slack"))
DEPRECATED_PYPI = frozenset({"mcp-server-sentry", "mcp-server-sqlite"})
_EXACT_NPM = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_EXACT_PYPI = re.compile(r"^\d+(?:\.\d+)*(?:[A-Za-z0-9.+!-]*)$")
_GIT_SHA = re.compile(r"[#@][0-9a-f]{40}$")
_LOCAL = re.compile(r"^(?:\.|/|~|file:|[A-Za-z]:[\\/])")
_NPM_VALUE = frozenset({"-p", "--package", "--registry", "--cache", "--userconfig", "-w",
                        "--workspace"})
_UV_VALUE = frozenset({"--from", "--with", "--with-requirements", "--with-editable", "--python",
                       "-p", "--index", "--index-url", "--default-index", "--extra-index-url",
                       "-i", "--find-links", "-f", "--directory", "--project", "--cache-dir",
                       "--config-file", "--constraints", "--overrides", "--env-file"})
_PIPX_VALUE = frozenset({"--spec", "--python", "--index-url", "--pip-args"})
_DOCKER_VALUE = frozenset({
    "-e", "--env", "--env-file", "-v", "--volume", "-p", "--publish", "-w", "--workdir", "-u",
    "--user", "--name", "--network", "--net", "--mount", "--entrypoint", "--platform", "-l",
    "--label", "--add-host", "--cpus", "-m", "--memory", "-h", "--hostname", "--pull",
    "--cap-add", "--cap-drop", "--device", "--dns", "--ipc", "--pid", "--restart", "--runtime",
    "--security-opt", "--shm-size", "--ulimit", "--tmpfs", "--log-driver", "--log-opt",
    "--gpus", "--group-add", "--stop-signal", "--cidfile"})


@dataclass(frozen=True)
class Launch:
    ecosystem: str  # npm | pypi | docker
    launcher: str
    spec: str
    index: int  # word that holds the spec


def launched(words: list[str]) -> Launch | None:
    """The package or image a launcher such as npx, uvx or docker run fetches and runs."""
    i = 0
    while i + 1 < len(words) and program_name(words[i]) == "cmd" and words[i + 1].lower() in (
            "/c", "/k"):
        i += 2
    if i >= len(words):
        return None
    name, args = program_name(words[i]), words[i + 1:]
    if name in ("npx", "bunx", "pnpx"):
        ecosystem, launcher, j, values, spec_option = "npm", name, i + 1, _NPM_VALUE, (
            "-p", "--package")
    elif name in ("pnpm", "yarn") and args[:1] == ["dlx"] or name == "bun" and args[:1] == [
            "x"]:
        ecosystem, launcher, j, values, spec_option = "npm", f"{name} {args[0]}", i + 2, (
            _NPM_VALUE), ("-p", "--package")
    elif name == "uvx" or name == "uv" and args[:2] == ["tool", "run"]:
        ecosystem, launcher, j, values, spec_option = "pypi", "uvx", i + (
            1 if name == "uvx" else 3), _UV_VALUE, ("--from",)
    elif name == "pipx" and args[:1] == ["run"]:
        ecosystem, launcher, j, values, spec_option = "pypi", "pipx run", i + 2, _PIPX_VALUE, (
            "--spec",)
    elif name in ("docker", "podman") and args[:1] == ["run"]:
        ecosystem, launcher, j, values, spec_option = "docker", f"{name} run", i + 2, (
            _DOCKER_VALUE), ()
    else:
        return None
    while j < len(words):
        word = words[j]
        if ecosystem == "npm" and word in ("-c", "--call"):
            return None  # runs a command line, not a package
        option, _, inline = word.partition("=")
        if option in spec_option:
            if inline:
                return Launch(ecosystem, launcher, inline, j)
            if j + 1 < len(words):
                return Launch(ecosystem, launcher, words[j + 1], j + 1)
            return None
        if word.startswith("-"):
            j += 2 if option in values and not inline else 1
            continue
        return Launch(ecosystem, launcher, word, j)
    return None


def package_name(launch: Launch) -> tuple[str, bool | None]:
    """The package's name, and whether the spec pins one release (None for local paths)."""
    spec = launch.spec
    if launch.ecosystem == "docker":
        return spec.split("@")[0], "@sha256:" in spec
    if _LOCAL.match(spec):
        return spec, None
    if re.match(r"^(?:github:|gitlab:|bitbucket:|git\+|git://|https?://)", spec) or (
            launch.ecosystem == "npm" and re.match(r"^[\w.-]+/[\w.-]+(?:#.*)?$", spec)):
        return spec, bool(_GIT_SHA.search(spec))
    if launch.ecosystem == "npm":
        match = re.match(r"^(@[^/@\s]+/[^@\s]+|[^@\s]+)(?:@(.*))?$", spec)
        if not match:
            return spec, False
        version = match.group(2)
        return match.group(1).lower(), bool(version and _EXACT_NPM.match(version))
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$", spec)
    if not match:
        return spec, False
    name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
    rest = match.group(3).strip()
    pinned = (rest.startswith("===") or rest.startswith("==") and _EXACT_PYPI.match(
        rest[2:].strip()) is not None and "*" not in rest) or (
        rest.startswith("@") and _EXACT_PYPI.match(rest[1:]) is not None)
    return name, bool(pinned)


REDIRECT_VARIABLES = frozenset({
    "ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL",
    "OPENAI_BASE_URL", "OPENAI_API_BASE", "GOOGLE_GEMINI_BASE_URL", "HTTPS_PROXY",
    "HTTP_PROXY", "ALL_PROXY"})
TLS_OFF = {"NODE_TLS_REJECT_UNAUTHORIZED": "0", "PYTHONHTTPSVERIFY": "0",
           "GIT_SSL_NO_VERIFY": "true"}
_PRELOAD = {
    "NODE_OPTIONS": re.compile(r"(?:^|\s)(?:-r|--require|--import|--loader|"
                               r"--experimental-loader)(?:[\s=]|$)"),
    "BASH_ENV": re.compile(r"\S"), "LD_PRELOAD": re.compile(r"\S"),
    "LD_AUDIT": re.compile(r"\S"), "DYLD_INSERT_LIBRARIES": re.compile(r"\S"),
    "PERL5OPT": re.compile(r"\S"), "RUBYOPT": re.compile(r"(?:^|\s)-r"),
    "JAVA_TOOL_OPTIONS": re.compile(r"-javaagent|-agentpath|-agentlib"),
    "_JAVA_OPTIONS": re.compile(r"-javaagent|-agentpath|-agentlib"),
    "JDK_JAVA_OPTIONS": re.compile(r"-javaagent|-agentpath|-agentlib"),
}
_NODE_PRELOAD = re.compile(r"(?:^|\s)(?:-r|--require|--import|--loader|--experimental-loader)"
                           r"(?:=|\s+)(['\"]?)([^\s'\"]+)\1")


def mask(value: str) -> str:
    """A URL without the user name, password or query, which can hold secrets."""
    value = re.sub(r"(://)[^/@\s]*@", r"\1…@", value)
    return re.sub(r"\?\S*", "?…", value)


def environment_hits(key: str, value: str, *, agent: bool) -> list[tuple[str, str]]:
    """(rule, reason) for a variable that loads code into programs, or, for the agent's own
    environment, sends its traffic elsewhere."""
    out = []
    pattern = _PRELOAD.get(key)
    if pattern and pattern.search(value):
        out.append(("BS-AG-008", f"{key} makes programs that read it load extra code"))
    if TLS_OFF.get(key) == value.strip().lower():
        out.append(("BS-AG-007", f"{key}={value.strip()} turns off TLS certificate checks"))
    if agent and key.upper() in REDIRECT_VARIABLES and value.strip():
        what = "proxy" if "PROXY" in key.upper() else "API endpoint"
        out.append(("BS-AG-007", f"sets the {what} to {mask(value.strip())}"))
    return out


def _env_file(path: Path, shown: str, text: str, found: Discovery, info: AgentFile) -> None:
    positions = Positions(text)
    for line_no in range(1, len(positions.line_starts) + 1):
        line = positions.line_text(line_no)
        match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$", line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        for rule, reason in environment_hits(key, value, agent=True):
            start = positions.line_starts[line_no - 1]
            found.hits.append((shown, CodeHit(
                rule, positions.region(start + match.start(1), start + len(line.rstrip())),
                f"{key}={mask(value)}", [reason, f"loaded by {info.trigger}"]), None))


# Configurations ----------------------------------------------------------------------------

CLAUDE_EVENTS = {
    "SessionStart": "the start or resume of every Claude Code session in this project",
    "SessionEnd": "the end of every Claude Code session in this project",
    "UserPromptSubmit": "every prompt sent to Claude Code in this project",
    "PreToolUse": "Claude Code tool calls in this project, before each one runs",
    "PostToolUse": "Claude Code tool calls in this project, after each one runs",
    "Notification": "Claude Code notifications in this project",
    "Stop": "the end of every Claude Code response in this project",
    "SubagentStop": "the end of every Claude Code subagent run in this project",
    "PreCompact": "Claude Code compacting its context in this project",
}
CLAUDE_HELPERS = {
    "apiKeyHelper": "Claude Code fetching an API key",
    "awsAuthRefresh": "Claude Code refreshing AWS credentials",
    "awsCredentialExport": "Claude Code loading AWS credentials",
    "otelHeadersHelper": "Claude Code sending telemetry",
}
PROJECT_DIR = re.compile(r"([\"']?)(?:\$\{?(?:CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT|"
                         r"CURSOR_PROJECT_DIR|GEMINI_PROJECT_DIR)\}?|\$\{workspaceFolder\})\1")
MAX_HOOK_DEPTH = 6


class _Config:
    def __init__(self, path: Path, shown: str, text: str, found: Discovery, display,
                 info: AgentFile) -> None:
        self.path, self.shown, self.text, self.found, self.display, self.info = (
            path, shown, text, found, display, info)
        self.positions = Positions(text)

    def read(self) -> jsonc.Node | None:
        try:
            node = jsonc.parse(self.text)
        except jsonc.JsoncError as exc:
            line = self.positions.region(exc.index, exc.index).line
            self.found.notes.append((self.shown, f"Not read as {self.info.label}: {exc} at "
                                                 f"line {line}. {self.info.tool or 'The tool'} "
                                                 "may still read it."))
            return None
        return node if isinstance(node.value, dict) else None

    def dispatch(self, root: jsonc.Node) -> None:
        kind = self.info.kind
        if kind == "claude":
            self.claude(root)
        elif kind == "mcp":
            for key in ("mcpServers", "servers", "mcp"):
                if root.get(key) is not None:
                    self.servers(root.get(key))
        elif kind == "gemini":
            self.servers(root.get("mcpServers"))
            self.hooks(root.get("hooks"), {})
        elif kind == "cursor-hooks":
            self.hooks(root.get("hooks"), {})
        elif kind == "vscode":
            self.vscode(root)

    # Positions ---------------------------------------------------------------------------

    def span(self, node: jsonc.Node) -> Region:
        return self.positions.region(node.start, node.end)

    def key(self, parent: jsonc.Node, key: str) -> Region:
        start, end = parent.key_span(key)
        return self.positions.region(start, end)

    def line(self, region: Region) -> str:
        return self.positions.line_text(region.line).strip()

    def offset(self, node: jsonc.Node) -> tuple[int, int] | None:
        """Where a JSON string's text starts, when the file holds it as written."""
        raw = self.text[node.start + 1:node.end - 1]
        if raw != node.text() or "\n" in raw:
            return None
        region = self.positions.region(node.start + 1, node.start + 1)
        return region.line - 1, region.column - 1

    def hit(self, rule: str, region: Region, via: list[str], entry: EntryPoint | None,
            evidence: str | None = None, level: Level | None = None) -> None:
        self.found.hits.append((self.shown, CodeHit(rule, region, clip(
            evidence if evidence is not None else self.line(region)), via, level=level),
            entry))

    # Commands ----------------------------------------------------------------------------

    def command(self, label: str, trigger: str, node: jsonc.Node, base: Path | None = None
                ) -> EntryPoint:
        """A shell command the tool runs on its own."""
        command = node.text() or ""
        region = self.span(node)
        entry = EntryPoint("agent", label, trigger, self.shown, region, command)
        self.found.entry_points.append(entry)
        self.hit("BS-AG-005", region, [f"runs on {trigger}"], entry)
        self.found.snippets.append((self.shown, Snippet(
            "shell", command, self.positions.line_region(region.line),
            f"{label} in {self.info.label}", self.offset(node)), entry))
        find_targets(self.found, entry, PROJECT_DIR.sub(".", command), base or self.info.root,
                     self.display)
        return entry

    def hooks(self, hooks: jsonc.Node | None, triggers: dict[str, str]) -> None:
        if hooks is None or not isinstance(hooks.value, dict):
            return
        for event, value in hooks.value.items():
            for node, matcher in _command_nodes(value, None, 0):
                label = f"{self.info.tool} {event} hook" + (
                    f" (matcher {matcher})" if matcher and matcher != "*" else "")
                trigger = triggers.get(event, f"the {event} event in {self.info.tool}")
                self.command(label, trigger + self.condition(), node)

    def condition(self) -> str:
        """When the tool starts honouring this file."""
        if self.info.label == "plugin hooks":
            return ", once the plugin is installed and enabled"
        return TRUSTED if self.info.kind in ("claude", "gemini") else ""

    def claude(self, root: jsonc.Node) -> None:
        self.hooks(root.get("hooks"), CLAUDE_EVENTS)
        status = root.get("statusLine")
        if status is not None and status.get("command") is not None and status.get(
                "command").text():
            self.command("Claude Code statusLine command", "every status line refresh in "
                         "Claude Code" + self.condition(), status.get("command"))
        for key, what in CLAUDE_HELPERS.items():
            node = root.get(key)
            if node is not None and node.text():
                self.command(f"Claude Code {key}", what + self.condition(), node)
        self.environment(root.get("env"), agent=True)
        permissions = root.get("permissions")
        if permissions is not None:
            mode = permissions.get("defaultMode")
            if mode is not None and mode.text() == "bypassPermissions":
                self.hit("BS-AG-006", self.span(mode), ["defaultMode bypassPermissions runs "
                                                        "every tool call without asking"], None)
            allow = permissions.get("allow")
            for item in allow.items() if allow is not None else []:
                if item.text() and _BROAD_SHELL.match(item.text()):
                    self.hit("BS-AG-006", self.span(item), [
                        f"the allow rule {item.text()} runs every shell command without "
                        "asking"], None)
        every = root.get("enableAllProjectMcpServers")
        if every is not None and every.value is True:
            self.hit("BS-AG-006", self.key(root, "enableAllProjectMcpServers"), [
                "starts every MCP server in the project's .mcp.json without asking"], None)
        listed = root.get("enabledMcpjsonServers")
        if listed is not None and listed.items():
            names = ", ".join(n.text() for n in listed.items() if n.text())
            self.hit("BS-AG-006", self.key(root, "enabledMcpjsonServers"), [
                f"starts these .mcp.json servers without asking: {names}"], None)

    def vscode(self, root: jsonc.Node) -> None:
        for key in ("chat.tools.autoApprove", "chat.tools.global.autoApprove"):
            node = root.get(key)
            if node is not None and node.value is True:
                self.hit("BS-AG-006", self.key(root, key), [
                    f"{key} runs Copilot agent tools and commands without asking",
                    "Whether VS Code honours it in workspace settings depends on its "
                    "version."], None)
        tasks = root.get("task.allowAutomaticTasks")
        if tasks is not None and tasks.text() == "on":
            self.hit("BS-AG-006", self.key(root, "task.allowAutomaticTasks"), [
                "runs folderOpen tasks without asking"], None)
        mcp = root.get("mcp")
        if mcp is not None:
            self.servers(mcp.get("servers"))

    def environment(self, env: jsonc.Node | None, *, agent: bool,
                    entry: EntryPoint | None = None) -> None:
        if env is None or not isinstance(env.value, dict):
            return
        for key, node in env.value.items():
            value = node.text()
            if value is None:
                continue
            for rule, reason in environment_hits(key, value, agent=agent):
                self.hit(rule, self.key(env, key), [reason], entry,
                         f"{key}={mask(value)}")
            if key == "NODE_OPTIONS":
                self.preload(value, self.key(env, key))

    def preload(self, value: str, region: Region) -> None:
        for match in _NODE_PRELOAD.finditer(value):
            target = target_path(self.info.root, match.group(2))
            if target is None:
                continue
            entry = EntryPoint("agent", f"NODE_OPTIONS preload in {self.info.label}",
                               "every Node.js process started with this environment",
                               self.shown, region, f"NODE_OPTIONS={value}")
            self.found.entry_points.append(entry)
            entry.targets.append(self.display(target))
            self.found.targets.append(Target(target, "javascript", entry))

    # MCP servers -------------------------------------------------------------------------

    def servers(self, servers: jsonc.Node | None) -> None:
        if servers is None or not isinstance(servers.value, dict):
            return
        for name, server in servers.value.items():
            if isinstance(server.value, dict):
                self.server(name, server, self.key(servers, name))

    def server(self, name: str, server: jsonc.Node, region: Region) -> None:
        command = server.get("command")
        url = next((server.get(k).text() for k in ("url", "httpUrl", "serverUrl")
                    if server.get(k) is not None and server.get(k).text()), None)
        if command is None:
            if url:
                self.found.entry_points.append(EntryPoint(
                    "agent", f"remote MCP server '{name}'", self.info.trigger, self.shown,
                    region, mask(url)))
            return
        nodes = [command] if command.text() is not None else [
            n for n in command.items() if n.text() is not None]
        args = server.get("args")
        nodes += [n for n in (args.items() if args is not None else []) if n.text() is not None]
        words = [n.text() for n in nodes]
        if not words or not words[0]:
            return
        single = len(words) == 1 and command.text() is not None
        line = words[0] if single else shell_join(words)
        entry = EntryPoint("agent", f"MCP server '{name}'", self.info.trigger, self.shown,
                           region, line)
        self.found.entry_points.append(entry)
        self.found.snippets.append((self.shown, Snippet(
            "shell", line, self.positions.line_region(region.line),
            f"MCP server '{name}' in {self.info.label}"), entry))
        base = self.info.root
        cwd = server.get("cwd")
        if cwd is not None and cwd.text():
            candidate = (base / PROJECT_DIR.sub(".", cwd.text())).resolve()
            try:
                candidate.relative_to(base.resolve())
                base = candidate
            except ValueError:
                pass
        find_targets(self.found, entry, PROJECT_DIR.sub(".", line), base, self.display)
        if single:
            words, nodes = split_command(words[0]), [command]
        self.launch(entry, words, nodes, region)
        self.environment(server.get("env") or server.get("environment"), agent=False,
                         entry=entry)

    def launch(self, entry: EntryPoint, words: list[str], nodes: list[jsonc.Node],
               region: Region) -> None:
        launch = launched(words)
        if launch is None:
            return
        name, pinned = package_name(launch)
        node = nodes[launch.index] if len(nodes) == len(words) else nodes[0]
        at = self.span(node)
        if pinned is False:
            what = ("the image tag can point at a different image at any time"
                    if launch.ecosystem == "docker" else
                    f"{launch.launcher} fetches the newest release of {name} at every start")
            self.hit("BS-MCP-001", at, [what], entry, launch.spec)
        if name in DEPRECATED_NPM and launch.ecosystem == "npm" or (
                name in DEPRECATED_PYPI and launch.ecosystem == "pypi"):
            self.hit("BS-MCP-002", at, [f"{name} is archived in "
                                        "modelcontextprotocol/servers-archived"], entry,
                     launch.spec)

    # Codex -------------------------------------------------------------------------------

    def codex(self) -> None:
        try:
            data = tomllib.loads(self.text)
        except tomllib.TOMLDecodeError as exc:
            self.found.notes.append((self.shown, f"Not read as {self.info.label}: {exc}. "
                                                 "Codex may still read it."))
            return
        servers = data.get("mcp_servers")
        if isinstance(servers, dict):
            for name, server in servers.items():
                if isinstance(server, dict):
                    self.codex_server(name, server)
        notify = data.get("notify")
        if isinstance(notify, list) and notify and all(isinstance(w, str) for w in notify):
            region = self.toml_line(r"notify\s*=")
            command = shell_join(notify)
            entry = EntryPoint("agent", "Codex notify command", "every Codex turn that "
                               "finishes" + ", once the project is trusted", self.shown, region,
                               command)
            self.found.entry_points.append(entry)
            self.hit("BS-AG-005", region, [f"runs on {entry.trigger}"], entry)
            self.found.snippets.append((self.shown, Snippet("shell", command, region,
                                                            "Codex notify command"), entry))
            find_targets(self.found, entry, command, self.info.root, self.display)
        for match in re.finditer(r'^\s*approval_policy\s*=\s*["\']never["\']', self.text,
                                 re.MULTILINE):
            region = self.positions.region(match.start() + len(match.group()) - len(
                match.group().lstrip()), match.end())
            self.hit("BS-AG-006", region, ["approval_policy never runs every command without "
                                           "asking"], None)

    def toml_line(self, pattern: str) -> Region:
        match = re.search(rf"^[ \t]*{pattern}", self.text, re.MULTILINE)
        if match is None:
            return self.positions.line_region(1)
        return self.positions.line_region(self.positions.region(match.end(), match.end()).line)

    def codex_server(self, name: str, server: dict) -> None:
        region = self.toml_line(rf"\[\s*mcp_servers\.(?:{re.escape(name)}|\"{re.escape(name)}\""
                                rf"|'{re.escape(name)}')\s*\]")
        command, args = server.get("command"), server.get("args", [])
        if not isinstance(command, str) or not isinstance(args, list):
            url = server.get("url")
            if isinstance(url, str):
                self.found.entry_points.append(EntryPoint(
                    "agent", f"remote MCP server '{name}'", self.info.trigger, self.shown,
                    region, mask(url)))
            return
        words = [command, *(a for a in args if isinstance(a, str))]
        line = shell_join(words)
        entry = EntryPoint("agent", f"MCP server '{name}'", self.info.trigger, self.shown,
                           region, line)
        self.found.entry_points.append(entry)
        self.found.snippets.append((self.shown, Snippet(
            "shell", line, region, f"MCP server '{name}' in {self.info.label}"), entry))
        find_targets(self.found, entry, line, self.info.root, self.display)
        launch = launched(words)
        if launch is not None:
            package, pinned = package_name(launch)
            if pinned is False:
                self.hit("BS-MCP-001", region, [f"{launch.launcher} fetches the newest "
                                                f"release of {package} at every start"], entry,
                         launch.spec)
            if package in DEPRECATED_NPM | DEPRECATED_PYPI:
                self.hit("BS-MCP-002", region, [f"{package} is archived in "
                                                "modelcontextprotocol/servers-archived"],
                         entry, launch.spec)
        env = server.get("env")
        if isinstance(env, dict):
            for key, value in env.items():
                if isinstance(value, str):
                    for rule, reason in environment_hits(key, value, agent=False):
                        self.hit(rule, region, [reason], entry, f"{key}={mask(value)}")


def _command_nodes(node: jsonc.Node, matcher: str | None, depth: int
                   ) -> list[tuple[jsonc.Node, str | None]]:
    """Every {"command": "..."} hook under an event, with the matcher it sits under."""
    if depth > MAX_HOOK_DEPTH:
        return []
    out: list[tuple[jsonc.Node, str | None]] = []
    if isinstance(node.value, dict):
        own = node.get("matcher")
        matcher = own.text() if own is not None and own.text() is not None else matcher
        command, kind = node.get("command"), node.get("type")
        if command is not None and command.text() and (kind is None or kind.text() == "command"):
            out.append((command, matcher))
        for key, value in node.value.items():
            if key != "command":
                out.extend(_command_nodes(value, matcher, depth + 1))
    else:
        for item in node.items():
            out.extend(_command_nodes(item, matcher, depth + 1))
    return out


__all__ = ["classify", "discover", "instruction_hits", "launched", "package_name"]

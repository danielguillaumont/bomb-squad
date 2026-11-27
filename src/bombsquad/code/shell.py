"""Shell analysis with tree-sitter-bash: npm scripts, hook scripts, `run:` steps.

The script is parsed, never run. Code embedded with `node -e`, `python -c` or a
PowerShell command line is returned as snippets for the matching analyzer.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from functools import cache

import tree_sitter
import tree_sitter_bash

from bombsquad.code.common import CodeHit, Snippet, clip, credential_reference
from bombsquad.textpos import Positions

DOWNLOADERS = frozenset({"curl", "wget", "fetch", "aria2c", "iwr", "invoke-webrequest"})
NETWORK_TOOLS = DOWNLOADERS | {"nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp",
                               "ftp", "rsync"}
INTERPRETERS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3",
                          "node", "nodejs", "bun", "deno", "perl", "ruby", "php", "pwsh",
                          "powershell", "iex", "source", ".", "eval"})
WRAPPERS = frozenset({"sudo", "doas", "env", "exec", "command", "nohup", "time", "nice"})
DECODERS = frozenset({"base64", "base32", "xxd", "openssl", "gunzip", "zcat", "uudecode"})


@cache
def _parser() -> tree_sitter.Parser:
    return tree_sitter.Parser(tree_sitter.Language(tree_sitter_bash.language()))


def _text(node) -> str:
    return node.text.decode("utf-8", "replace")


def _walk(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _unquote(word: str) -> str:
    """The word as the program receives it, for simple quoted and unquoted words."""
    if len(word) >= 2 and word[0] == word[-1] == "'":
        return word[1:-1]
    if len(word) >= 2 and word[0] == word[-1] == '"':
        # Inside double quotes a backslash escapes only $ ` " \ and newline.
        return re.sub(r'\\([$`"\\\n])', r"\1", word[1:-1])
    if "\\" in word and not word.startswith(("'", '"')):
        return re.sub(r"\\(.)", r"\1", word)
    return word


def _words(command) -> list[str]:
    """Command name (after wrappers such as sudo or env VAR=x) and its arguments."""
    words = [_unquote(_text(c)) for c in command.named_children
             if c.type not in ("variable_assignment", "file_redirect", "heredoc_redirect",
                               "herestring_redirect")]
    while words and (words[0].rsplit("/", 1)[-1] in WRAPPERS):
        words = words[1:]
        while words and ("=" in words[0] and not words[0].startswith("-")
                         or words[0].startswith("-")):
            words = words[1:]
    return words


def _name(command) -> str:
    words = _words(command)
    return words[0].rsplit("/", 1)[-1].lower() if words else ""


def _decodes(command) -> bool:
    words = [w.lower() for w in _words(command)]
    if not words:
        return False
    name = words[0].rsplit("/", 1)[-1]
    if name in ("base64", "base32"):
        return any(w in ("-d", "--decode", "-D") or w.startswith("--decode") for w in words[1:])
    if name == "xxd":
        return "-r" in words
    if name == "openssl":
        return "-d" in words or "base64" in words
    return name in ("gunzip", "zcat", "uudecode")


@dataclass
class ShellResult:
    hits: list[CodeHit] = field(default_factory=list)
    snippets: list[Snippet] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class _Analysis:
    def __init__(self, text: str) -> None:
        self.text = text
        self.positions = Positions(text)
        self.tree = _parser().parse(text.encode("utf-8"))
        self.result = ShellResult()
        self.consumed: set[int] = set()

    def region(self, node):
        return self.positions.region_utf8(node.start_point[0] + 1, node.start_point[1],
                                          node.end_point[0] + 1, node.end_point[1])

    def hit(self, rule_id: str, node, via=()) -> None:
        self.result.hits.append(CodeHit(rule_id, self.region(node), clip(_text(node)), list(via)))

    def commands_in(self, node) -> list:
        return [n for n in _walk(node) if n.type == "command"]

    def pipeline(self, node) -> None:
        commands = [c for c in node.named_children if c.type == "command"]
        names = [_name(c) for c in commands]
        for j, name in enumerate(names):
            if name not in INTERPRETERS:
                continue
            for i in range(j):
                if names[i] in DOWNLOADERS:
                    self.hit("BS-NET-002", node, [f"{names[i]} output piped into {name}"])
                    self.consumed.update(c.start_byte for c in commands)
                    return
                if _decodes(commands[i]):
                    self.hit("BS-EN-003", node, [f"{names[i]} output piped into {name}"])
                    self.consumed.update(c.start_byte for c in commands)
                    return

    def command(self, node) -> None:
        if node.start_byte in self.consumed:
            return
        words = _words(node)
        if not words:
            return
        name = words[0].rsplit("/", 1)[-1].lower()
        args = words[1:]
        substitutions = [n for n in _walk(node) if n.type in ("command_substitution",
                                                               "process_substitution")]
        if name in INTERPRETERS and substitutions:
            inner = [c for s in substitutions for c in self.commands_in(s)]
            if any(_name(c) in DOWNLOADERS for c in inner):
                self.hit("BS-NET-002", node, [f"{name} runs content fetched inside $( ) or <( )"])
                self.consumed.update(c.start_byte for c in inner)
                return
            if any(_decodes(c) for c in inner):
                self.hit("BS-EN-003", node, [f"{name} runs content decoded inside $( )"])
                self.consumed.update(c.start_byte for c in inner)
                return
        if name == "eval" and args:
            self.hit("BS-DE-006", node, ["eval runs text as shell code"])
        if name in NETWORK_TOOLS:
            self.hit("BS-NET-003", node, [f"runs {name}"])
        if name in ("env", "printenv") and all(a.startswith("-") for a in args):
            self.hit("BS-ENV-001", node, [f"{name} prints every variable"])
        if name == "export" and args == ["-p"] or name == "declare" and args in (["-x"], ["-p"]):
            self.hit("BS-ENV-001", node, [f"{name} {' '.join(args)} prints every variable"])
        self.embedded(node, name, args)

    def embedded(self, node, name: str, args: list[str]) -> None:
        """Code passed on the command line to another interpreter."""
        region = self.region(node)
        line = region.line
        if name in ("node", "nodejs", "bun", "deno"):
            for i, arg in enumerate(args[:-1]):
                if arg in ("-e", "--eval", "-p", "--print"):
                    self.result.snippets.append(Snippet("javascript", args[i + 1], region,
                                                        f"{name} {arg} code at line {line}"))
                    return
        elif name in ("python", "python3", "py"):
            for i, arg in enumerate(args[:-1]):
                if arg == "-c":
                    self.result.snippets.append(Snippet("python", args[i + 1], region,
                                                        f"{name} -c code at line {line}"))
                    return
        elif name in ("pwsh", "powershell", "pwsh.exe", "powershell.exe"):
            self.result.snippets.append(Snippet("powershell", _text(node), region,
                                                f"{name} command line at line {line}"))
        elif name in ("sh", "bash", "zsh", "dash") and "-c" in args:
            index = args.index("-c")
            if index + 1 < len(args):
                self.result.snippets.append(Snippet("shell", args[index + 1], region,
                                                    f"{name} -c script at line {line}"))

    def run(self) -> ShellResult:
        root = self.tree.root_node
        if root.has_error:
            self.result.notes.append("The script has syntax errors; rules ran on what parsed.")
        nodes = list(_walk(root))
        for node in nodes:
            if node.type == "pipeline":
                self.pipeline(node)
        for node in nodes:
            if node.type == "command":
                self.command(node)
            elif node.type == "file_redirect" and "/dev/tcp/" in _text(node) or (
                    node.type == "file_redirect" and "/dev/udp/" in _text(node)):
                self.hit("BS-NET-003", node, ["redirects to a /dev/tcp or /dev/udp socket"])
            elif node.type in ("word", "string", "raw_string", "simple_expansion", "expansion"):
                if node.parent is not None and node.parent.type in ("string",):
                    continue
                reference = credential_reference(_text(node))
                if reference:
                    self.hit("BS-CR-001", node, [f"names {reference}"])
        return self.result


def analyze_shell(text: str) -> ShellResult:
    return _Analysis(text).run()


def split_command(command: str) -> list[str]:
    """Words of a one-line command, for finding the files an npm script runs."""
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()

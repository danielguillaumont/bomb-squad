"""What inventory hands to the analyzers: entry points, the files and embedded code they
run, and findings about the entry points themselves."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from bombsquad.code.common import CodeHit, Snippet
from bombsquad.code.shell import command_words
from bombsquad.model import EntryPoint

LANGUAGE_BY_SUFFIX = {
    ".js": "javascript", ".cjs": "javascript", ".mjs": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".mts": "javascript", ".cts": "javascript", ".tsx": "javascript",
    ".py": "python", ".sh": "shell", ".bash": "shell",
    ".ps1": "powershell", ".psm1": "powershell",
}


@dataclass
class Target:
    path: Path
    language: str
    entry: EntryPoint


@dataclass
class Discovery:
    entry_points: list[EntryPoint] = field(default_factory=list)
    targets: list[Target] = field(default_factory=list)
    snippets: list[tuple[str, Snippet, EntryPoint]] = field(default_factory=list)
    hits: list[tuple[str, CodeHit, EntryPoint | None]] = field(default_factory=list)
    notes: list[tuple[str, str]] = field(default_factory=list)
    # Placeholders that stand in for GitHub Actions ${{ }} expressions while embedded code
    # is parsed, and the original text, which evidence shows.
    expressions: dict[str, str] = field(default_factory=dict)

    def placeholder(self, original: str) -> str:
        """A word-safe stand-in for `original`, padded to the same length when possible so
        that columns in the parsed code still line up with the file."""
        token = f"_BS{len(self.expressions) + 1}_"
        token += "_" * max(0, len(original) - len(token))
        self.expressions[token] = original
        return token


def quote_word(word: str) -> str:
    """A word as a POSIX shell would need it written to keep it one word."""
    if word and not re.search(r"[\s\"'$`\\;&|<>()*?#~]", word):
        return word
    return '"' + re.sub(r'(["\\$`])', r"\\\1", word) + '"'


def shell_join(words: list[str]) -> str:
    return " ".join(quote_word(w) for w in words)


def target_path(base: Path, word: str) -> Path | None:
    """A file named on a command line, if it exists inside `base`."""
    word = word.strip("'\"").rstrip(";&|)").lstrip("(")
    if not word or word.startswith("-") or "://" in word:
        return None
    candidate = (base / word).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError:
        return None  # outside the package or repository
    if candidate.is_file() and candidate.suffix.lower() in LANGUAGE_BY_SUFFIX:
        return candidate
    return None


# Programs whose first plain argument is a script they run.
SCRIPT_RUNNERS = frozenset({"node", "nodejs", "bun", "deno", "tsx", "ts-node", "python",
                            "python3", "py", "sh", "bash", "zsh", "dash", "ksh", "source", ".",
                            "pwsh", "powershell", "perl", "ruby", "php"})
# Options after which the next argument is code or a module, not a file.
CODE_OPTIONS = frozenset({"-e", "--eval", "-p", "--print", "-c", "-m", "-command",
                          "-encodedcommand", "-ec", "-enc"})
# `<tool> run <program> ...` runs the program in an environment.
ENV_RUNNERS = frozenset({"uv", "poetry", "pipenv", "pdm", "hatch", "rye"})


def program_name(word: str) -> str:
    return word.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")


def run_files(words: list[str], depth: int = 0) -> list[str]:
    """Words of one command that name a file it runs: the command itself, or the script
    given to an interpreter. Files only passed as data (`cat x.sh`) are not counted."""
    if not words or depth > 3:
        return []
    name = program_name(words[0])
    rest = words[1:]
    if name in ENV_RUNNERS and rest[:1] == ["run"] or name in ("npx", "pnpx", "bunx"):
        rest = rest[1:] if rest[:1] == ["run"] else rest
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        return run_files(rest, depth + 1)
    if name in ("deno", "bun") and rest[:1] == ["run"]:
        rest = rest[1:]
    out = [words[0]]
    if name not in SCRIPT_RUNNERS:
        return out
    for i, arg in enumerate(rest):
        lower = arg.lower()
        if lower in CODE_OPTIONS:
            break
        if name in ("pwsh", "powershell") and lower in ("-file", "-f"):
            out.extend(rest[i + 1:i + 2])
            break
        if not arg.startswith("-"):
            out.append(arg)
            break
    return out


def find_targets(found: Discovery, entry: EntryPoint, command: str, base: Path, display,
                 language: str | None = None) -> None:
    """Make every file the command runs a target of the entry point."""
    for word in (w for words in command_words(command) for w in run_files(words)):
        target = target_path(base, word)
        if target is None:
            continue
        shown = display(target)
        if shown not in entry.targets:
            entry.targets.append(shown)
        found.targets.append(Target(target, language or LANGUAGE_BY_SUFFIX[
            target.suffix.lower()], entry))

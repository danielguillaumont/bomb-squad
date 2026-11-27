"""Pieces shared by the JavaScript, Python and shell analyzers."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from bombsquad.model import Level, Region
from bombsquad.textpos import Positions

EVIDENCE_LIMIT = 300


@dataclass
class CodeHit:
    rule_id: str
    region: Region
    evidence: str
    via: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    level: Level | None = None


@dataclass(frozen=True)
class Snippet:
    """Code embedded in another file, such as `node -e "..."` in an npm script."""

    language: str  # javascript | python | shell | powershell
    text: str
    region: Region  # where the snippet sits in its file
    origin: str
    # (line delta, column delta) from the snippet's own positions to the file's, when the
    # snippet is a verbatim block of the file. Findings then point at the exact line;
    # otherwise they point at `region`.
    offset: tuple[int, int] | None = None


def command_line(words: list[str]) -> str:
    """An argument list as one shell command line, quoted so the shell analyzer reads the
    same words back: single quotes, or double quotes for a word that holds single quotes
    and nothing the shell would expand inside double quotes."""
    out = []
    for word in words:
        if word and re.fullmatch(r"[\w@%+=:,./-]+", word):
            out.append(word)
        elif "'" not in word:
            out.append(f"'{word}'")
        elif not re.search(r'["$`\\!]', word):
            out.append(f'"{word}"')
        else:
            out.append("'" + word.replace("'", "'\"'\"'") + "'")
    return " ".join(out)


def clip(text: str) -> str:
    text = " ".join(text.split()) if "\n" not in text.strip() else text.strip()
    return text if len(text) <= EVIDENCE_LIMIT else text[:EVIDENCE_LIMIT] + "…"


# Files and variables that credential stealers read. Paths match as substrings, in either
# slash direction; variable names match whole words.
CREDENTIAL_PATHS = (
    ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".aws/credentials", ".aws/config",
    ".ssh/", "id_rsa", "id_ed25519", "id_ecdsa", ".docker/config.json", ".kube/config",
    ".config/gh/hosts.yml", ".azure/", "gcloud/credentials", "application_default_credentials",
    "login data", "wallet.dat", "169.254.169.254", "metadata.google.internal",
)
CREDENTIAL_VARIABLES = (
    "GITHUB_TOKEN", "GH_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN", "PYPI_TOKEN", "PYPI_API_TOKEN",
    "TWINE_PASSWORD", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN", "SYSTEM_OIDCREQUESTURI",
    "SYSTEM_ACCESSTOKEN", "IDENTITY_ENDPOINT", "IDENTITY_HEADER", "CI_JOB_TOKEN",
    "VAULT_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
)
_VARIABLE_PATTERN = re.compile(r"\b(" + "|".join(CREDENTIAL_VARIABLES) + r")\b")


def credential_reference(text: str) -> str | None:
    """The credential file or variable a string refers to, if any."""
    lower = text.lower().replace("\\", "/")
    if lower.strip("/~ ") in (".ssh", ".aws", ".kube", ".docker", ".azure", ".gnupg"):
        return lower.strip("/~ ")
    for path in CREDENTIAL_PATHS:
        if path in lower:
            return path
    match = _VARIABLE_PATTERN.search(text)
    return match.group(1) if match else None


# Characters that do not display, or that change display order (Trojan Source).
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_INVISIBLE = {0x200B, 0x200C, 0x200E, 0x200F, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E}
_TAGS = range(0xE0000, 0xE0080)
_SUPPLEMENTARY_SELECTORS = range(0xE0100, 0xE01F0)
_SELECTORS = range(0xFE00, 0xFE10)


def _kind(ch: str) -> str | None:
    cp = ord(ch)
    if cp in _BIDI:
        return "bidi"
    if cp in _TAGS:
        return "tag"
    if cp in _SUPPLEMENTARY_SELECTORS or cp in _SELECTORS:
        return "selector"
    if cp in _INVISIBLE or (cp == 0xFEFF):
        return "invisible"
    if 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0x10FFFF:
        return "private"
    return None


_BLACK_FLAG, _CANCEL_TAG, _ZWNJ = 0x1F3F4, 0xE007F, 0x200C


def _in_script(ch: str) -> bool:
    """A letter or mark of a script from Hebrew onwards, where the zero-width non-joiner
    is part of normal spelling (Persian, Indic and Southeast Asian scripts among them)."""
    return ord(ch) >= 0x0590 and unicodedata.category(ch)[0] in "LM"


def _expected(line: str) -> set[int]:
    """Positions of characters that are part of ordinary text: tag characters in a flag
    emoji (U+1F3F4, tags, U+E007F), and a zero-width non-joiner next to a letter of a
    script that uses it."""
    ok: set[int] = set()
    for i, ch in enumerate(line):
        if ord(ch) == _BLACK_FLAG:
            j = i + 1
            while j < len(line) and (0xE0061 <= ord(line[j]) <= 0xE007A or
                                     0xE0030 <= ord(line[j]) <= 0xE0039):
                j += 1
            # Subdivision codes are short (gbeng, usca); a longer run is not a flag.
            if j < len(line) and ord(line[j]) == _CANCEL_TAG and 2 <= j - i - 1 <= 7:
                ok.update(range(i + 1, j + 1))
        elif ord(ch) == _ZWNJ and (i > 0 and _in_script(line[i - 1]) or
                                   i + 1 < len(line) and _in_script(line[i + 1])):
            ok.add(i)
    return ok


def hidden_characters(text: str, positions: Positions) -> list[CodeHit]:
    """Report invisible and direction-changing characters, one hit per affected line.

    Single variation selectors and private-use characters are common in emoji and icon
    fonts, so only runs of four or more are reported. A byte order mark at the start of
    a file, flag emoji built from tag characters, and zero-width non-joiners inside words
    of scripts that need them are ignored.
    """
    hits: list[CodeHit] = []
    for line_no in range(1, len(positions.line_starts) + 1):
        line = positions.line_text(line_no)
        if line.isascii():
            continue
        found: dict[str, int] = {}
        first: int | None = None
        run_kind, run_len = None, 0
        expected = _expected(line)
        for i, ch in enumerate(line):
            kind = _kind(ch)
            if kind == "invisible" and ord(ch) == 0xFEFF and line_no == 1 and i == 0:
                kind = None
            if i in expected:
                kind = None
            if kind in ("selector", "private"):
                run_len = run_len + 1 if run_kind == kind else 1
                run_kind = kind
                if run_len == 4:
                    found[kind] = found.get(kind, 0) + 4
                    first = i - 3 if first is None else first
                elif run_len > 4:
                    found[kind] += 1
                continue
            run_kind, run_len = None, 0
            if kind:
                found[kind] = found.get(kind, 0) + 1
                first = i if first is None else first
        if not found:
            continue
        start = positions.line_starts[line_no - 1]
        names = {"bidi": "direction-changing", "tag": "Unicode tag", "selector":
                 "variation selector", "invisible": "zero-width", "private": "private-use"}
        described = ", ".join(f"{n} {names[k]}" for k, n in sorted(found.items()))
        visible = "".join(c if _kind(c) is None else f"<U+{ord(c):04X}>" for c in line)
        serious = {"bidi", "tag", "selector", "private"} & set(found)
        hits.append(CodeHit(
            "BS-UC-001", positions.region(start + (first or 0), start + len(line)),
            clip(visible), [f"{described} character{'s' if sum(found.values()) > 1 else ''}"],
            level=None if serious else Level.REVIEW,
        ))
    return hits


_PADDING = re.compile(r"[ \t]{100,}(?=\S)")


def _previous_indent(text: str, positions: Positions, line_no: int) -> int:
    """The leading whitespace of the nearest non-blank line above, or 0."""
    for number in range(line_no - 1, 0, -1):
        line = positions.line_text(number)
        if line.strip():
            return len(line) - len(line.lstrip(" \t"))
    return 0


def whitespace_padding(text: str, positions: Positions) -> list[CodeHit]:
    hits: list[CodeHit] = []
    for match in _PADDING.finditer(text):
        line_no = positions.region(match.start(), match.start()).line
        line_start = positions.line_starts[line_no - 1]
        if text[line_start:match.start()].strip() == "" and (
                len(match.group()) < 200 or
                len(match.group()) - _previous_indent(text, positions, line_no) < 100):
            continue  # deep indentation, or nesting that deepens step by step: not padding
        hidden_start = match.end()
        line_end = text.find("\n", hidden_start)
        line_end = len(text) if line_end < 0 else line_end
        hits.append(CodeHit(
            "BS-OB-001", positions.region(hidden_start, line_end),
            clip(text[hidden_start:line_end]),
            [f"{len(match.group())} whitespace characters before it on line {line_no}"],
        ))
    return hits


_BLOB = re.compile(r"[A-Za-z0-9+/=]{2000,}|(?:\\x[0-9a-fA-F]{2}){500,}|[0-9a-fA-F]{2000,}")
_OBFUSCATOR_NAME = re.compile(r"\b_0x[0-9a-f]{4,6}\b")


def packed_code(text: str, positions: Positions) -> list[CodeHit]:
    """Large encoded blobs, obfuscator-style names, or very long minified lines."""
    reasons: list[str] = []
    anchor = 0
    blob = _BLOB.search(text)
    if blob:
        reasons.append(f"an encoded blob of {len(blob.group())} characters")
        anchor = blob.start()
    names = _OBFUSCATOR_NAME.findall(text)
    if len(names) >= 10:
        reasons.append(f"{len(names)} obfuscator-style names such as {names[0]}")
        anchor = text.find(names[0]) if not reasons[:-1] else anchor
    longest = max((len(positions.line_text(n)) for n in range(1, len(positions.line_starts) + 1)),
                  default=0)
    if longest > 5000:
        reasons.append(f"a line of {longest} characters")
    if not reasons:
        return []
    line = positions.region(anchor, anchor).line
    return [CodeHit("BS-OB-002", positions.line_region(line),
                    clip(positions.line_text(line)[:200]), ["; ".join(reasons)])]

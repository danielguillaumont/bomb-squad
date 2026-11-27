"""Apply the PowerShell rules to parsed documents and follow decoded content."""

from __future__ import annotations

import base64
import binascii
import re
import shlex
from dataclasses import dataclass, field

from bombsquad.catalogue import ALL_RULES as RULES
from bombsquad.code.common import credential_reference
from bombsquad.model import FileResult, Finding, Level, Region
from bombsquad.powershell import names
from bombsquad.powershell.parser import (
    Command,
    Invocation,
    ParsedDocument,
    Span,
    parse_documents,
)

MAX_DEPTH = 3
BATCH_SIZE = 100
EVIDENCE_LIMIT = 400

SWITCHES = (
    "asjob", "confirm", "debug", "disablekeepalive", "force", "nonewwindow", "passthru",
    "recurse", "usebasicparsing", "usedefaultcredentials", "verbose", "wait", "whatif",
)

# powershell.exe / pwsh switches that take a value, so the next token is not a command.
POWERSHELL_VALUE_SWITCHES = (
    "configurationname", "custompipename", "encodedarguments", "executionpolicy",
    "inputformat", "outputformat", "psconsolefile", "settingsfile", "version", "windowstyle",
    "workingdirectory",
)
POWERSHELL_VALUE_ALIASES = ("ep", "ex", "if", "of", "v", "w", "wd")

DOWNLOAD_MEMBERS = frozenset({
    "downloaddata", "downloaddataasync", "downloaddatataskasync", "downloadfile",
    "downloadfileasync", "downloadfiletaskasync", "downloadstring", "downloadstringasync",
    "downloadstringtaskasync", "getbytearrayasync", "getstreamasync", "getstringasync",
    "openread", "openreadasync",
})

# Names of internals that are only touched to disable AMSI or script logging.
AMSI_TOKENS = (
    "amsiutils", "amsiinitfailed", "amsicontext", "amsiscanbuffer", "amsiopensession",
    "amsi.dll", "cachedgrouppolicysettings", "scriptblocklogging",
)


@dataclass
class Hit:
    rule_id: str
    span: Span
    evidence: str
    via: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    level: Level | None = None


@dataclass(frozen=True)
class Child:
    anchor: Span
    text: str
    origin: str
    quiet: bool = False  # do not report it when it is not PowerShell


@dataclass(frozen=True)
class Context:
    path: str
    anchor: Region | None
    via: tuple[str, ...]
    depth: int
    quiet: bool = False
    tag: object = None


@dataclass(frozen=True)
class Source:
    """PowerShell to analyse: a whole file, or code embedded in another file."""

    path: str
    text: str
    anchor: Region | None = None  # where embedded code sits in its file
    via: tuple[str, ...] = ()
    tag: object = None  # returned with each finding, for the caller's bookkeeping


def _clip(text: str) -> str:
    text = text.strip()
    return text if len(text) <= EVIDENCE_LIMIT else text[:EVIDENCE_LIMIT] + "…"


def _slice(text: str, span: Span) -> str:
    """Source text for a span given in UTF-16 offsets."""
    data = text.encode("utf-16-le")
    return data[span.start * 2:span.end * 2].decode("utf-16-le", errors="replace")


def _b64(value: str | None) -> bytes | None:
    if not value:
        return None
    compact = re.sub(r"\s", "", value)
    if len(compact) < 4 or not re.fullmatch(r"[A-Za-z0-9+/]+=*", compact):
        return None
    compact += "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None


def _readable(text: str) -> bool:
    if not text:
        return False
    ok = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return ok / len(text) >= 0.95


def _decode_utf16(value: str | None) -> str | None:
    data = _b64(value)
    if data is None or len(data) % 2:
        return None
    try:
        text = data.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    return text if _readable(text) else None


def _decode_any(data: bytes) -> str | None:
    """Text from decoded base64: UTF-16LE when it looks like it, otherwise UTF-8."""
    odd_zeros = data[1::2].count(0)
    candidates = ("utf-16-le", "utf-8") if data and odd_zeros >= len(data) // 4 else ("utf-8",)
    for encoding in candidates:
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _readable(text):
            return text
    return None


def _is_switch(name: str) -> bool:
    lower = name.lower()
    return any(s.startswith(lower) for s in SWITCHES)


def _named(cmd: Command, *full_names: str, aliases: tuple[str, ...] = ()
           ) -> tuple[str | None, bool]:
    """Value of a named parameter, accepting unambiguous prefixes of at least two letters."""
    elements = cmd.elements
    for i, el in enumerate(elements):
        if el.kind != "parameter" or not el.name:
            continue
        lower = el.name.lower()
        if lower in aliases or (len(lower) >= 2 and any(f.startswith(lower) for f in full_names)):
            if el.has_argument:
                return el.value, True
            if i + 1 < len(elements) and elements[i + 1].kind == "value":
                return elements[i + 1].value, True
            return None, True
    return None, False


def _positionals(cmd: Command) -> list:
    out = []
    skip_next = False
    for el in cmd.elements:
        if el.kind == "parameter":
            skip_next = not el.has_argument and not _is_switch(el.name or "")
            continue
        if skip_next:
            skip_next = False
            continue
        out.append(el)
    return out


def _tokens(cmd: Command) -> list[str]:
    """Arguments of a native command as the program would receive them."""
    tokens: list[str] = []
    for el in cmd.elements:
        if el.kind == "parameter":
            tokens.append("-" + (el.name or ""))
            if el.has_argument:
                tokens.append(el.value if el.value is not None else el.text)
        else:
            tokens.append(el.value if el.value is not None else el.text)
    return tokens


def _path_argument(cmd: Command) -> str | None:
    path, found = _named(cmd, "path", "literalpath", "pspath", aliases=("lp",))
    if found:
        return path
    positionals = _positionals(cmd)
    return positionals[0].value if positionals else None


def _command_variables(cmd: Command) -> set[str]:
    return {v for el in cmd.elements for v in el.variables}


class _DocumentAnalysis:
    def __init__(self, doc: ParsedDocument) -> None:
        self.doc = doc
        self.hits: list[Hit] = []
        self.children: list[Child] = []
        self.downloads: list[Span] = []
        self.executors: list[tuple[Hit, Command | Invocation]] = []

    # Helpers -----------------------------------------------------------------------------

    def hit(self, rule_id: str, span: Span, evidence: str, via=(), limitations=(),
            level: Level | None = None) -> Hit:
        h = Hit(rule_id, span, _clip(evidence), list(via), list(limitations), level)
        self.hits.append(h)
        return h

    def registry_hit(self, cls: str, cmd: Command, via, limitations) -> None:
        rule_id = {
            "defender": "BS-SS-001", "defender-exclusion": "BS-SS-002", "logging": "BS-AV-001",
            "autostart": "BS-RG-002",
        }.get(cls, "BS-RG-001")
        self.hit(rule_id, cmd.span, cmd.text, via, limitations)

    # Commands ----------------------------------------------------------------------------

    def command(self, cmd: Command) -> None:
        if cmd.name is None:
            if cmd.operator in ("Ampersand", "Dot"):
                self.hit("BS-DE-003", cmd.span, cmd.text)
            return
        resolved = names.resolve(cmd.name)
        via = list(resolved.via)
        if cmd.name_source == "folded":
            via.insert(0, f"command name built from string literals: {cmd.name_text.strip()} "
                          f"is {cmd.name}")
        limitations = []
        if resolved.name.lower() in self.doc.functions or cmd.name.lower() in self.doc.functions:
            limitations.append(
                f"This script defines a function named {cmd.name}; that function would run "
                "instead of the built-in command."
            )
        if resolved.kind == "cmdlet":
            self.cmdlet(cmd, resolved.name, via, limitations)
        elif resolved.kind == "native":
            self.native(cmd, resolved.name, via, limitations)

    def cmdlet(self, cmd: Command, name: str, via, limitations) -> None:
        if name in ("Remove-Item", "Set-ItemProperty", "New-ItemProperty", "Remove-ItemProperty",
                    "New-Item"):
            path = _path_argument(cmd)
            cls = names.registry_class(path)
            if cls:
                self.registry_hit(cls, cmd, via, limitations)
            elif name == "Remove-Item":
                self.hit("BS-FS-001", cmd.span, cmd.text, via, limitations)
            elif path is None and name != "New-Item":
                self.hit("BS-RG-001", cmd.span, cmd.text, via, [
                    *limitations, "The path is not a literal, so it may not be a registry path."])
        elif name in ("Set-MpPreference", "Add-MpPreference"):
            params = [el.name.lower() for el in cmd.elements if el.kind == "parameter" and el.name]
            exclusion = any(p.startswith("ex") for p in params)
            self.hit("BS-SS-002" if exclusion else "BS-SS-001", cmd.span, cmd.text, via,
                     limitations)
        elif name in ("New-LocalUser", "Add-LocalGroupMember"):
            admin = any("admin" in (el.value or "").lower() for el in cmd.elements)
            self.hit("BS-ID-001", cmd.span, cmd.text, via, limitations,
                     Level.HIGH if admin else None)
        elif name in ("Register-ScheduledTask", "Set-ScheduledTask", "New-Service",
                      "Set-Service"):
            self.hit("BS-TS-001", cmd.span, cmd.text, via, limitations)
        elif name == "Invoke-Expression":
            h = self.hit("BS-DE-001", cmd.span, cmd.text, via, limitations)
            self.executors.append((h, cmd))
            text, found = _named(cmd, "command")
            if not found:
                positionals = _positionals(cmd)
                text = positionals[0].value if positionals else None
            if text:
                self.children.append(
                    Child(cmd.span, text, f"text passed to Invoke-Expression at line "
                                          f"{cmd.span.line}"))
        elif name in ("Get-ChildItem", "Get-Item"):
            path = (_path_argument(cmd) or "").lower().replace("\\", "/").rstrip("/*")
            if path in ("env:", "env:/"):
                self.hit("BS-ENV-001", cmd.span, cmd.text, [*via, "lists the Env: drive"],
                         limitations)
        elif name in ("Invoke-WebRequest", "Invoke-RestMethod", "Start-BitsTransfer"):
            self.downloads.append(cmd.span)
        elif name == "Add-Type":
            params = [el.name.lower() for el in cmd.elements if el.kind == "parameter" and el.name]
            assembly_only = (params and all(p.startswith("as") or p == "an" for p in params)
                             and not _positionals(cmd))
            if not assembly_only:
                self.hit("BS-DE-004", cmd.span, cmd.text, via, limitations)
        elif name == "Import-Module":
            values = [el.value or "" for el in cmd.elements if el.kind == "value"]
            if any(re.search(r"[\\/]|\.(psm1|psd1|ps1|dll)$", v, re.IGNORECASE) for v in values):
                self.hit("BS-DE-005", cmd.span, cmd.text, via, limitations)
        elif name == "Start-Process":
            target, found = _named(cmd, "filepath")
            if not found:
                positionals = _positionals(cmd)
                target = positionals[0].value if positionals else None
            if target and names.resolve(target).name in ("powershell", "pwsh"):
                arguments, _ = _named(cmd, "argumentlist", aliases=("args",))
                if arguments is None:
                    positionals = _positionals(cmd)
                    arguments = positionals[1].value if len(positionals) > 1 else None
                if arguments:
                    try:
                        tokens = shlex.split(arguments, posix=False)
                    except ValueError:
                        tokens = arguments.split()
                    tokens = [t.strip("'\"") for t in tokens]
                    self.powershell_cli(cmd, tokens, names.resolve(target).name, via,
                                        limitations)

    def native(self, cmd: Command, tool: str, via, limitations) -> None:
        tokens = _tokens(cmd)
        lower = [t.lower() for t in tokens]
        if tool == "reg":
            if lower and lower[0] in ("add", "delete", "import", "restore", "load", "copy"):
                key = tokens[1] if len(tokens) > 1 else None
                self.registry_hit(names.registry_class(key) or "registry", cmd, via, limitations)
        elif tool == "schtasks":
            if any(names.strip_switch(t) in ("create", "change") for t in lower):
                self.hit("BS-TS-001", cmd.span, cmd.text, via, limitations)
        elif tool == "sc":
            if lower and lower[0] in ("create", "config", "failure", "delete"):
                self.hit("BS-TS-001", cmd.span, cmd.text, via, limitations)
        elif tool in ("net", "net1"):
            if (len(lower) >= 2 and lower[0] in ("user", "localgroup")
                    and any(t in ("/add", "/delete", "/active:yes") for t in lower)):
                admin = lower[0] == "localgroup" and "admin" in lower[1]
                self.hit("BS-ID-001", cmd.span, cmd.text, via, limitations,
                         Level.HIGH if admin else None)
        elif tool in ("powershell", "pwsh"):
            self.powershell_cli(cmd, tokens, tool, via, limitations)
        elif tool in ("curl", "wget"):
            self.downloads.append(cmd.span)
        elif tool == "bitsadmin":
            if any(names.strip_switch(t) in ("transfer", "addfile", "download") for t in lower):
                self.downloads.append(cmd.span)
        elif tool == "certutil":
            if any(names.strip_switch(t) in ("urlcache", "verifyctl") for t in lower):
                self.downloads.append(cmd.span)

    def powershell_cli(self, cmd: Command, tokens: list[str], tool: str, via,
                       limitations) -> None:
        """Arguments to powershell.exe or pwsh: encoded commands and command text."""
        line = cmd.span.line
        i = 0
        while i < len(tokens):
            token = tokens[i]
            is_switch = token[:1] in ("-", "/", "–", "—", "―")
            if is_switch and names.is_encoded_command_switch(token):
                value = tokens[i + 1] if i + 1 < len(tokens) else None
                decoded = _decode_utf16(value)
                if decoded is None:
                    self.hit("BS-EN-001", cmd.span, cmd.text, via, [
                        *limitations, "The encoded text could not be decoded as UTF-16 base64."])
                else:
                    self.hit("BS-EN-001", cmd.span, cmd.text,
                             [*via, f"decoded: {_clip(decoded)}"], limitations)
                    self.children.append(
                        Child(cmd.span, decoded, f"decoded from -EncodedCommand at line {line}"))
                i += 2
                continue
            if is_switch and names.is_command_switch(token):
                text = " ".join(tokens[i + 1:]).strip()
                if text and text != "-":
                    self.children.append(Child(cmd.span, text, f"-Command text at line {line}"))
                return
            if is_switch:
                switch = names.strip_switch(token)
                takes_value = switch in POWERSHELL_VALUE_ALIASES or (
                    len(switch) >= 2 and any(s.startswith(switch)
                                             for s in POWERSHELL_VALUE_SWITCHES))
                i += 2 if takes_value else 1
                continue
            if tool == "powershell":
                # Windows PowerShell treats the first plain argument as the start of -Command.
                text = " ".join(tokens[i:]).strip()
                if text:
                    self.children.append(Child(cmd.span, text, f"command text at line {line}"))
            return

    # Member invocations ------------------------------------------------------------------

    def invocation(self, inv: Invocation) -> None:
        member = (inv.member or "").lower()
        type_name = (inv.type_name or "").lower()
        literal = inv.arguments[0] if inv.arguments else None
        if member in DOWNLOAD_MEMBERS or (
                member == "create" and type_name.endswith(("webrequest", "httpwebrequest"))):
            self.downloads.append(inv.span)
        elif (member == "create" and type_name in ("scriptblock",
                                                    "system.management.automation.scriptblock")
              ) or member == "newscriptblock":
            h = self.hit("BS-DE-002", inv.span, inv.text)
            self.executors.append((h, inv))
            if literal:
                self.children.append(Child(inv.span, literal,
                                           f"script block text at line {inv.span.line}"))
        elif member == "invokescript":
            h = self.hit("BS-DE-001", inv.span, inv.text)
            self.executors.append((h, inv))
            if literal:
                self.children.append(Child(inv.span, literal,
                                           f"text passed to InvokeScript at line {inv.span.line}"))
        elif member == "getenvironmentvariables":
            self.hit("BS-ENV-001", inv.span, inv.text, ["reads every environment variable"])
        elif member in ("load", "loadfile", "loadfrom", "unsafeloadfrom") and type_name.endswith(
                "reflection.assembly"):
            self.hit("BS-DE-004", inv.span, inv.text)
        elif member == "frombase64string" and literal:
            data = _b64(literal)
            if data is None or len(data) < 4:
                return
            text = _decode_any(data)
            if text is None:
                self.hit("BS-EN-002", inv.span, inv.text,
                         [f"decodes to {len(data)} bytes of binary data, not analysed"])
            else:
                self.hit("BS-EN-002", inv.span, inv.text, [f"decoded: {_clip(text)}"])
                self.children.append(Child(inv.span, text,
                                           f"base64 decoded at line {inv.span.line}", quiet=True))

    # Cross-cutting -----------------------------------------------------------------------

    def cradles(self) -> None:
        """Turn 'evaluate text' into 'download and run' when the text is a download."""
        consumed: set[int] = set()
        for h, node in self.executors:
            found: tuple[int, Span, str] | None = None
            for idx, dspan in enumerate(self.downloads):
                if node.span.contains(dspan) and dspan != node.span:
                    found = (idx, node.span, f"downloads at line {dspan.line} inside the call")
                elif (isinstance(node, Command) and node.pipeline is not None
                      and node.pipeline.contains(dspan) and dspan.end <= node.span.start):
                    found = (idx, node.pipeline, f"download at line {dspan.line} piped into it")
                if found:
                    break
            if not found:
                variables = (_command_variables(node) if isinstance(node, Command)
                             else set(node.variables))
                for assignment in self.doc.assignments:
                    if (assignment.variable not in variables
                            or assignment.value_span.end > node.span.start):
                        continue
                    for idx, dspan in enumerate(self.downloads):
                        if assignment.value_span.contains(dspan):
                            found = (idx, node.span, f"${assignment.variable} holds a download "
                                                     f"from line {dspan.line}")
                            break
                    if found:
                        break
            if found:
                idx, span, how = found
                consumed.add(idx)
                h.rule_id = "BS-NET-002"
                h.span = span
                h.evidence = _clip(_slice(self.doc.text, span))
                h.via.append(how)
        for idx, dspan in enumerate(self.downloads):
            if idx not in consumed:
                self.hit("BS-NET-001", dspan, _slice(self.doc.text, dspan))

    def tampering_strings(self) -> None:
        for s in self.doc.strings:
            lower = s.value.lower()
            via = [f"string built from literals: {_clip(s.value)}"] if s.folded else []
            if any(token in lower for token in AMSI_TOKENS):
                self.hit("BS-AV-001", s.span, _slice(self.doc.text, s.span), via)
            reference = credential_reference(s.value)
            if reference:
                self.hit("BS-CR-001", s.span, _slice(self.doc.text, s.span),
                         [*via, f"names {reference}"])

    def dedupe(self) -> list[Hit]:
        """Keep one hit per rule where one hit's span contains another's."""
        kept: list[Hit] = []
        for h in sorted(self.hits, key=lambda x: (x.span.start, -x.span.end)):
            if any(k.rule_id == h.rule_id and k.span.contains(h.span) for k in kept):
                continue
            kept.append(h)
        return kept

    def run(self) -> tuple[list[Hit], list[Child]]:
        for using in self.doc.blanked_usings:
            self.hit("BS-DE-005", using.span, using.text, [
                f"using {using.kind} statement, blanked before parsing so the parser did not "
                "open the file it names"])
        for cmd in self.doc.commands:
            self.command(cmd)
        for inv in self.doc.invocations:
            self.invocation(inv)
        self.cradles()
        self.tampering_strings()
        return self.dedupe(), self.children


def analyze_document(doc: ParsedDocument) -> tuple[list[Hit], list[Child]]:
    return _DocumentAnalysis(doc).run()


def _finding(h: Hit, ctx: Context) -> Finding:
    rule = RULES[h.rule_id]
    region = ctx.anchor or h.span.region
    return Finding(
        rule=rule,
        path=ctx.path,
        region=region,
        evidence=h.evidence,
        level=h.level or rule.level,
        via=[*ctx.via, *h.via],
        limitations=h.limitations,
    )


def analyze_sources(sources: list[tuple[str, str]], results: dict[str, FileResult]
                    ) -> tuple[dict, list[Finding]]:
    """Analyse (path, text) pairs. Updates `results` and returns parser info and findings."""
    parser_info, tagged = analyze_tagged([Source(path, text) for path, text in sources], results)
    return parser_info, [f for f, _ in tagged]


def analyze_tagged(sources: list[Source], results: dict[str, FileResult]
                   ) -> tuple[dict, list[tuple[Finding, object]]]:
    """Analyse sources, returning each finding with the tag of the source it came from."""
    parser_info: dict = {}
    findings: list[tuple[Finding, object]] = []
    pending: list[tuple[str, str, Context]] = [
        (str(i), s.text, Context(s.path, s.anchor, s.via, 0, tag=s.tag))
        for i, s in enumerate(sources)
    ]
    while pending:
        next_round: list[tuple[str, str, Context]] = []
        for start in range(0, len(pending), BATCH_SIZE):
            batch = pending[start:start + BATCH_SIZE]
            contexts = {doc_id: ctx for doc_id, _, ctx in batch}
            parser_info, parsed = parse_documents([(doc_id, text) for doc_id, text, _ in batch])
            for doc in parsed:
                ctx = contexts[doc.id]
                result = results[ctx.path]
                # Rules still run on whatever the parser could read: skipping files with parse
                # errors would let a deliberate error (or a blanked `using module` that a
                # class depends on) hide the rest of the file.
                if doc.parse_errors:
                    if ctx.anchor is None:
                        result.parse_errors = doc.parse_errors
                        result.notes.append(
                            "The file does not parse, so PowerShell would refuse to run it as "
                            "written. Rules were applied to the parts the parser could read.")
                    elif ctx.quiet:
                        continue  # decoded base64 that is not PowerShell
                    else:
                        what = ctx.via[-1] if ctx.via else "embedded PowerShell"
                        result.notes.append(
                            f"Content ({what}) has parse errors. Rules were applied to "
                            "the parts the parser could read.")
                hits, children = analyze_document(doc)
                findings.extend((_finding(h, ctx), ctx.tag) for h in hits)
                if children and ctx.depth >= MAX_DEPTH:
                    result.notes.append(
                        f"Content nested more than {MAX_DEPTH} levels deep was not analysed.")
                    continue
                for n, child in enumerate(children):
                    origin = child.origin if ctx.anchor is None else (
                        child.origin + " of that content")
                    next_round.append((
                        f"{doc.id}.{n}", child.text,
                        Context(ctx.path, ctx.anchor or child.anchor.region,
                                (*ctx.via, origin), ctx.depth + 1, child.quiet, ctx.tag),
                    ))
        pending = next_round
    findings.sort(key=lambda t: (t[0].path, t[0].region.line, t[0].region.column, t[0].rule.id))
    return parser_info, findings

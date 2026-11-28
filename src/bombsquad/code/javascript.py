"""JavaScript and TypeScript analysis with tree-sitter. The code is parsed, never run."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cache

import tree_sitter
import tree_sitter_javascript
import tree_sitter_typescript

from bombsquad.code.common import (
    CodeHit,
    Snippet,
    clip,
    command_line,
    credential_reference,
    packed_code,
)
from bombsquad.textpos import Positions

NETWORK_MODULES = frozenset({
    "http", "https", "http2", "net", "tls", "dgram", "dns", "axios", "node-fetch", "got",
    "request", "undici", "ws", "superagent", "needle", "phin", "socket.io-client",
})
PROCESS_MODULES = frozenset({"child_process"})
SHELL_FUNCTIONS = frozenset({"exec", "execSync"})  # a command line, run by the shell
ARGV_FUNCTIONS = frozenset({"spawn", "spawnSync", "execFile", "execFileSync"})
VM_MODULES = frozenset({"vm"})
NETWORK_GLOBALS = frozenset({"fetch", "WebSocket", "XMLHttpRequest", "EventSource"})
ENV_SERIALIZERS = frozenset({
    "JSON.stringify", "Object.keys", "Object.values", "Object.entries", "util.inspect",
    "console.log", "Object.getOwnPropertyNames",
})
DECODERS = re.compile(r"atob\(|base64|fromcharcode|inflate|gunzip|decompress|['\"]hex['\"]",
                      re.IGNORECASE)
# Literals a value is held in on its way to a call: `{ env: process.env }`, `[...]`,
# `{ ...process.env }`, `(process.env)`.
VALUE_WRAPPERS = frozenset({"pair", "object", "array", "spread_element",
                            "parenthesized_expression"})
TS_SUFFIXES = (".ts", ".mts", ".cts")
TSX_SUFFIXES = (".tsx",)


@cache
def _parser(kind: str) -> tree_sitter.Parser:
    language = {
        "js": tree_sitter_javascript.language,
        "ts": tree_sitter_typescript.language_typescript,
        "tsx": tree_sitter_typescript.language_tsx,
    }[kind]()
    return tree_sitter.Parser(tree_sitter.Language(language))


def _kind_for(path: str) -> str:
    lower = path.lower()
    if lower.endswith(TSX_SUFFIXES):
        return "tsx"
    if lower.endswith(TS_SUFFIXES):
        return "ts"
    return "js"


def _module_name(raw: str) -> str:
    name = raw[5:] if raw.startswith("node:") else raw
    return name.split("/")[0] if not name.startswith("@") else "/".join(name.split("/")[:2])


def _string_value(node) -> str | None:
    if node is None:
        return None
    if node.type == "string":
        return node.text.decode("utf-8", "replace")[1:-1]
    if node.type == "template_string" and not any(
            c.type == "template_substitution" for c in node.children):
        return node.text.decode("utf-8", "replace")[1:-1]
    return None


def _strings(node) -> list[str] | None:
    """The values of an array of string literals, or None when any element is not one."""
    if node is None or node.type != "array":
        return [] if node is not None and node.type == "object" else None
    values = [_string_value(c) for c in node.named_children]
    return None if None in values else values  # type: ignore[return-value]


def _text(node) -> str:
    return node.text.decode("utf-8", "replace")


def _walk(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


@dataclass
class JsResult:
    hits: list[CodeHit] = field(default_factory=list)
    relative_imports: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Command lines passed to child_process as literals, for the shell analyzer.
    snippets: list[Snippet] = field(default_factory=list)


class _Analysis:
    def __init__(self, text: str, path: str) -> None:
        self.text = text
        self.positions = Positions(text)
        self.tree = _parser(_kind_for(path)).parse(text.encode("utf-8"))
        self.result = JsResult()
        self.aliases: dict[str, str] = {}  # local name -> module or module.member
        self.seen: set[tuple[str, int]] = set()
        self.env_holders: set[str] = set()  # variables holding process.env, whole or in a value
        # Calls that serialise or send, with the variables in their arguments, checked
        # against env_holders once every variable is known.
        self.sink_calls: list[tuple[object, str, set[str]]] = []

    def region(self, node):
        return self.positions.region_utf8(node.start_point[0] + 1, node.start_point[1],
                                          node.end_point[0] + 1, node.end_point[1])

    def hit(self, rule_id: str, node, via=(), evidence: str | None = None) -> None:
        key = (rule_id, node.start_byte)
        if key in self.seen:
            return
        self.seen.add(key)
        self.result.hits.append(CodeHit(rule_id, self.region(node),
                                        clip(evidence or _text(node)), list(via)))

    # Modules -----------------------------------------------------------------------------

    def module_used(self, raw: str, node) -> None:
        if raw.startswith("."):
            self.result.relative_imports.append(raw)
            return
        module = _module_name(raw)
        if module in NETWORK_MODULES:
            self.hit("BS-NET-003", node, [f"loads the {module} module"])
        elif module in PROCESS_MODULES:
            self.hit("BS-PRC-001", node, [f"loads the {module} module"])

    def bind(self, declarator) -> None:
        """Record `const x = require('m')` and `const {a} = require('m')`."""
        value = declarator.child_by_field_name("value")
        name = declarator.child_by_field_name("name")
        module = self.required_module(value)
        if module is None or name is None:
            return
        if name.type == "identifier":
            self.aliases[_text(name)] = module
        elif name.type == "object_pattern":
            for prop in name.named_children:
                key = prop.child_by_field_name("key") if prop.type == "pair_pattern" else prop
                local = prop.child_by_field_name("value") if prop.type == "pair_pattern" else prop
                if key is not None and local is not None and local.type in (
                        "identifier", "shorthand_property_identifier_pattern"):
                    self.aliases[_text(local)] = f"{module}.{_text(key)}"

    def required_module(self, node) -> str | None:
        if node is None or node.type != "call_expression":
            return None
        function = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if function is None or _text(function) != "require" or args is None:
            return None
        first = args.named_children[0] if args.named_children else None
        raw = _string_value(first)
        return _module_name(raw) if raw and not raw.startswith(".") else None

    def resolve(self, node) -> str:
        """Dotted name of a callee, with local aliases replaced by their module."""
        text = re.sub(r"\s+", "", _text(node))
        head, _, rest = text.partition(".")
        if head in self.aliases:
            return self.aliases[head] + ("." + rest if rest else "")
        if node.type == "member_expression":
            obj = node.child_by_field_name("object")
            module = self.required_module(obj)
            prop = node.child_by_field_name("property")
            if module and prop is not None:
                return f"{module}.{_text(prop)}"
        return text

    # Rules -------------------------------------------------------------------------------

    def call(self, node) -> None:
        function = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if function is None:
            return
        name = self.resolve(function)
        self.note_sink_call(node, name, args)
        first = args.named_children[0] if args is not None and args.named_children else None
        if _text(function) == "require" and first is not None:
            raw = _string_value(first)
            if raw:
                self.module_used(raw, node)
            return
        if function.type == "import" and first is not None:
            raw = _string_value(first)
            if raw:
                self.module_used(raw, node)
            return
        if name in NETWORK_GLOBALS or name == "navigator.sendBeacon":
            self.hit("BS-NET-003", node, [f"calls {name}"])
        elif name.split(".")[0] in PROCESS_MODULES or name in ("Bun.spawn", "Bun.spawnSync"):
            self.hit("BS-PRC-001", node, [f"calls {name}"])
            command = self.command(name, args)
            if command:
                region = self.region(node)
                self.result.snippets.append(Snippet("shell", command, region,
                                                    f"{name} command at line {region.line}"))
        elif name in ("eval", "Function", "globalThis.eval", "window.eval") or (
                name.split(".")[0] in VM_MODULES and name.split(".")[-1] in (
                "runInThisContext", "runInNewContext", "runInContext", "compileFunction")):
            self.dynamic(node, first, name)

    def command(self, name: str, args) -> str | None:
        """The command line a child_process call runs, when it is written out literally."""
        values = args.named_children if args is not None else []
        if not values:
            return None
        function = name.split(".")[-1]
        if function in SHELL_FUNCTIONS:
            return _string_value(values[0])
        if name in ("Bun.spawn", "Bun.spawnSync"):
            words = _strings(values[0])
        elif function in ARGV_FUNCTIONS:
            program = _string_value(values[0])
            rest = _strings(values[1]) if len(values) > 1 else []
            words = [program, *rest] if program is not None and rest is not None else None
        else:
            return None
        return command_line(words) if words else None

    def dynamic(self, node, first, name: str) -> None:
        if first is not None and _string_value(first) is not None and name == "eval":
            return  # eval of a fixed string literal
        argument_text = _text(node.child_by_field_name("arguments") or node)
        if DECODERS.search(argument_text):
            self.hit("BS-EN-003", node, [f"{name} runs decoded data"])
        else:
            self.hit("BS-DE-006", node, [f"calls {name}"])

    def new(self, node) -> None:
        constructor = node.child_by_field_name("constructor")
        if constructor is None:
            return
        name = self.resolve(constructor)
        args = node.child_by_field_name("arguments")
        first = args.named_children[0] if args is not None and args.named_children else None
        if name in NETWORK_GLOBALS:
            self.hit("BS-NET-003", node, [f"creates a {name}"])
        elif name == "Function" or name in ("vm.Script",) or name.endswith(".Script") and (
                name.split(".")[0] in VM_MODULES):
            self.dynamic(node, first, name)

    def environment(self, node) -> None:
        """process.env used as a whole and serialised, rather than read one key at a time."""
        parent = node.parent
        if parent is None:
            return
        if parent.type in ("member_expression", "subscript_expression") and (
                parent.child_by_field_name("object") == node):
            prop = parent.child_by_field_name("property") or parent.child_by_field_name("index")
            if prop is not None:
                reference = credential_reference(_text(prop))
                if reference:
                    self.hit("BS-CR-001", parent, [f"reads {reference}"])
            return
        how = None
        if parent.type == "arguments" and parent.parent is not None:
            callee = parent.parent.child_by_field_name("function")
            if callee is not None and self.resolve(callee) in ENV_SERIALIZERS:
                how = f"passed to {self.resolve(callee)}"
        elif parent.type in ("for_in_statement", "template_substitution", "binary_expression"):
            how = "iterated or turned into text"
        if how:
            self.hit("BS-ENV-001", parent.parent if parent.type == "arguments" else parent,
                     [f"process.env {how}"])
            return
        # Held in a value (an object, array or spread) that a call serialises or sends, or
        # that a variable keeps. A child process's `{ env: process.env }` is neither.
        holder, inner = parent, node
        while holder is not None and holder.type in VALUE_WRAPPERS:
            inner, holder = holder, holder.parent
        if holder is None:
            return
        if holder.type == "arguments" and holder.parent is not None:
            callee = holder.parent.child_by_field_name("function")
            sink = self.sink(self.resolve(callee)) if callee is not None else None
            if sink:
                self.hit("BS-ENV-001", holder.parent, [f"process.env, held in a value, {sink}"])
        elif holder.type == "variable_declarator" and holder.child_by_field_name("value") == inner:
            name = holder.child_by_field_name("name")
            if name is not None and name.type == "identifier":
                self.env_holders.add(_text(name))

    def sink(self, name: str) -> str | None:
        """How a call carries its arguments out: serialised, or sent over the network."""
        if name in ENV_SERIALIZERS:
            return f"serialised by {name}"
        if (name in NETWORK_GLOBALS or name == "navigator.sendBeacon"
                or name.split(".")[0] in NETWORK_MODULES):
            return f"sent with {name}"
        return None

    def note_sink_call(self, node, name: str, args) -> None:
        """Remember the variables a serialising or sending call is given, at any depth of
        object and array literals, to check once every variable holding process.env is
        known."""
        if args is None or not self.sink(name):
            return
        names: set[str] = set()
        stack = list(args.named_children)
        while stack:
            child = stack.pop()
            if child.type in ("identifier", "shorthand_property_identifier"):
                names.add(_text(child))
            elif child.type in VALUE_WRAPPERS:
                key = child.child_by_field_name("key") if child.type == "pair" else None
                stack.extend(c for c in child.named_children if c != key)
        if names:
            self.sink_calls.append((node, name, names))

    def run(self) -> JsResult:
        root = self.tree.root_node
        if root.has_error:
            self.result.notes.append("The file has syntax errors; rules ran on what parsed.")
        nodes = list(_walk(root))
        for node in nodes:  # aliases first, so calls before their binding still resolve
            if node.type == "variable_declarator":
                self.bind(node)
            elif node.type == "import_statement":
                source = node.child_by_field_name("source")
                raw = _string_value(source)
                if raw:
                    self.module_used(raw, node)
                    if not raw.startswith("."):
                        module = _module_name(raw)
                        for ident in (n for n in _walk(node) if n.type == "identifier"):
                            self.aliases[_text(ident)] = module
        for node in nodes:
            if node.type == "call_expression":
                self.call(node)
            elif node.type == "new_expression":
                self.new(node)
            elif node.type == "member_expression" and re.sub(r"\s", "", _text(node)) in (
                    "process.env", "globalThis.process.env"):
                self.environment(node)
            elif node.type in ("string_fragment",):
                reference = credential_reference(_text(node))
                if reference:
                    self.hit("BS-CR-001", node.parent or node, [f"names {reference}"])
        for call, name, names in self.sink_calls:
            held = sorted(names & self.env_holders)
            if held:
                self.hit("BS-ENV-001", call,
                         [f"{held[0]} holds process.env, and is {self.sink(name)}"])
        self.result.hits.extend(packed_code(self.text, self.positions))
        return self.result


def analyze_javascript(text: str, path: str) -> JsResult:
    return _Analysis(text, path).run()

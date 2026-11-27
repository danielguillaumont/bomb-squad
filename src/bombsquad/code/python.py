"""Python analysis with the standard library's `ast` module. The code is parsed, never run."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from bombsquad.code.common import CodeHit, clip, credential_reference, packed_code
from bombsquad.textpos import Positions

NETWORK_MODULES = frozenset({
    "socket", "ssl", "urllib.request", "http.client", "requests", "httpx", "aiohttp",
    "urllib3", "ftplib", "smtplib", "telnetlib", "paramiko", "websocket", "websockets",
    "pycurl",
})
PROCESS_CALLS = (
    "subprocess.", "os.system", "os.popen", "os.exec", "os.spawn", "os.startfile",
    "os.posix_spawn", "pty.spawn", "asyncio.create_subprocess_",
)
DECODE_CALLS = (
    "base64.", "codecs.decode", "zlib.decompress", "marshal.loads", "bytes.fromhex",
    "binascii.", "lzma.decompress", "bz2.decompress", "gzip.decompress", "pickle.loads",
)
ENV_SERIALIZERS = frozenset({"json.dumps", "str", "repr", "print", "pprint.pprint",
                             "pprint.pformat"})


@dataclass
class PyResult:
    hits: list[CodeHit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class _Analysis(ast.NodeVisitor):
    def __init__(self, text: str) -> None:
        self.text = text
        self.positions = Positions(text)
        self.result = PyResult()
        self.aliases: dict[str, str] = {}
        self.seen: set[tuple[str, int, int]] = set()

    def region(self, node: ast.AST):
        end_line = getattr(node, "end_lineno", None) or node.lineno
        end_col = getattr(node, "end_col_offset", None) or node.col_offset
        return self.positions.region_utf8(node.lineno, node.col_offset, end_line, end_col)

    def hit(self, rule_id: str, node: ast.AST, via=()) -> None:
        key = (rule_id, node.lineno, node.col_offset)
        if key in self.seen:
            return
        self.seen.add(key)
        source = ast.get_source_segment(self.text, node) or ""
        self.result.hits.append(CodeHit(rule_id, self.region(node), clip(source), list(via)))

    def dotted(self, node: ast.AST) -> str | None:
        parts: list[str] = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        head = self.aliases.get(node.id, node.id)
        return ".".join([head, *reversed(parts)])

    def is_environ(self, node: ast.AST) -> bool:
        return self.dotted(node) == "os.environ"

    # Imports -----------------------------------------------------------------------------

    def network_module(self, module: str, node: ast.AST) -> None:
        for candidate in NETWORK_MODULES:
            if module == candidate or module.startswith(candidate + "."):
                self.hit("BS-NET-003", node, [f"imports {module}"])
                return

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = (
                alias.name if alias.asname else alias.name.split(".")[0])
            self.network_module(alias.name, node)
            if alias.name in ("subprocess", "pty"):
                self.hit("BS-PRC-001", node, [f"imports {alias.name}"])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            self.aliases[alias.asname or alias.name] = full
            self.network_module(full, node)
            self.network_module(module, node)
        if module in ("subprocess", "pty"):
            self.hit("BS-PRC-001", node, [f"imports from {module}"])

    # Calls and values --------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        name = self.dotted(node.func) or ""
        first = node.args[0] if node.args else None
        if name.startswith(PROCESS_CALLS):
            self.hit("BS-PRC-001", node, [f"calls {name}"])
        elif name in ("exec", "eval", "compile", "builtins.exec", "builtins.eval"):
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                decoded = any(
                    isinstance(n, ast.Call) and (self.dotted(n.func) or "").startswith(
                        DECODE_CALLS)
                    for n in ast.walk(node))
                self.hit("BS-EN-003" if decoded else "BS-DE-006", node,
                         [f"{name} runs decoded data" if decoded else f"calls {name}"])
        if name in ENV_SERIALIZERS and any(self.is_environ(a) for a in node.args):
            self.hit("BS-ENV-001", node, [f"os.environ passed to {name}"])
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("items", "keys",
                                                                       "values") and (
                self.is_environ(node.func.value)):
            self.hit("BS-ENV-001", node, [f"os.environ.{node.func.attr}()"])
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if self.is_environ(node.iter):
            self.hit("BS-ENV-001", node.iter, ["iterates os.environ"])
        self.generic_visit(node)

    def visit_FormattedValue(self, node: ast.FormattedValue) -> None:
        if self.is_environ(node.value):
            self.hit("BS-ENV-001", node.value, ["os.environ formatted into text"])
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            reference = credential_reference(node.value)
            if reference:
                self.hit("BS-CR-001", node, [f"names {reference}"])

    def run(self) -> PyResult:
        try:
            tree = ast.parse(self.text)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
            self.result.notes.append(f"Could not parse as Python ({type(exc).__name__}); "
                                     "only text rules ran.")
            return self.result
        try:
            self.visit(tree)
        except RecursionError:
            self.result.notes.append("The code is nested too deeply to analyse fully; "
                                     "rules ran on the outer levels only.")
        self.result.hits.extend(packed_code(self.text, self.positions))
        return self.result


def analyze_python(text: str) -> PyResult:
    return _Analysis(text).run()

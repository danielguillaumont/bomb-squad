"""Python analysis with the standard library's `ast` module. The code is parsed, never run."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

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
# Calls whose first argument is a command line run by the shell.
SHELL_CALLS = frozenset({"os.system", "os.popen", "subprocess.getoutput",
                         "subprocess.getstatusoutput", "asyncio.create_subprocess_shell"})
# Calls whose positional arguments are the program and its arguments.
ARGV_CALLS = frozenset({"asyncio.create_subprocess_exec"})
EXECL_CALLS = frozenset({"os.execl", "os.execlp", "os.execle", "os.execlpe"})
ENV_SERIALIZERS = frozenset({"json.dumps", "str", "repr", "print", "pprint.pprint",
                             "pprint.pformat", "urllib.parse.urlencode", "pickle.dumps"})


@dataclass
class PyResult:
    hits: list[CodeHit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Command lines passed to process calls as literals, for the shell analyzer.
    snippets: list[Snippet] = field(default_factory=list)
    # (module, level) for each import: level 0 is absolute, 1 is `from . import`.
    imports: list[tuple[str, int]] = field(default_factory=list)
    # exec of a file the code opens by a path written in it, relative to the file's
    # folder, with the BS-DE-006 hit to report if that file is not in the scan.
    exec_files: list[tuple[str, CodeHit]] = field(default_factory=list)


class _Analysis(ast.NodeVisitor):
    def __init__(self, text: str) -> None:
        self.text = text
        self.positions = Positions(text)
        self.result = PyResult()
        self.aliases: dict[str, str] = {}
        self.seen: set[tuple[str, int, int]] = set()
        self.defined: set[str] = set()  # functions and classes the file defines itself
        self.paths: dict[str, str] = {}  # variable -> path; "" is the file's own folder
        self.opened: dict[str, str] = {}  # file object variable -> path
        self.env_holders: set[str] = set()  # variables holding os.environ, whole or in a value

    def region(self, node: ast.AST):
        end_line = getattr(node, "end_lineno", None) or node.lineno
        end_col = getattr(node, "end_col_offset", None) or node.col_offset
        return self.positions.region_utf8(node.lineno, node.col_offset, end_line, end_col)

    def hit(self, rule_id: str, node: ast.AST, via=()) -> CodeHit | None:
        key = (rule_id, node.lineno, node.col_offset)
        if key in self.seen:
            return None
        self.seen.add(key)
        source = ast.get_source_segment(self.text, node) or ""
        found = CodeHit(rule_id, self.region(node), clip(source), list(via))
        self.result.hits.append(found)
        return found

    # Paths -------------------------------------------------------------------------------

    def path_of(self, node: ast.AST) -> str | None:
        """A path written out in the code: string literals joined with os.path.join or
        `/`, where anything built from __file__ is the file's own folder (""). None when
        it depends on anything else."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return self.paths.get(node.id)
        if any(isinstance(n, ast.Name) and n.id == "__file__" for n in ast.walk(node)) and (
                not (isinstance(node, ast.Call) and self.dotted(node.func) in (
                    "os.path.join", "join"))) and not isinstance(node, ast.BinOp):
            return ""
        parts: list[ast.AST] = []
        if isinstance(node, ast.Call) and self.dotted(node.func) in ("os.path.join", "join"):
            parts = list(node.args)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            parts = [node.left, node.right]
        values = [self.path_of(part) for part in parts]
        if not parts or None in values:
            return None
        return "/".join(v for v in values if v)  # type: ignore[misc]

    def opened_path(self, node: ast.AST) -> str | None:
        """The path of `open(path)` or of a variable bound to one."""
        if isinstance(node, ast.Name):
            return self.opened.get(node.id)
        if isinstance(node, ast.Call) and self.dotted(node.func) in (
                "open", "io.open", "codecs.open") and node.args:
            return self.path_of(node.args[0])
        return None

    def prepare(self, tree: ast.AST) -> None:
        """Names the file defines, and paths and opened files bound to variables, in
        source order, before the rules run."""
        nodes = sorted((n for n in ast.walk(tree) if hasattr(n, "lineno")),
                       key=lambda n: (n.lineno, n.col_offset))
        for node in nodes:
            # Import aliases too, as the visitor sets them, so `from os import environ`
            # resolves in the variables below.
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.aliases[alias.asname or alias.name.split(".")[0]] = (
                        alias.name if alias.asname else alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    self.aliases[alias.asname or alias.name] = (
                        f"{node.module}.{alias.name}" if node.module else alias.name)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                self.defined.add(node.name)
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(
                    node.targets[0], ast.Name):
                name = node.targets[0].id
                if self.holds_environ(node.value):
                    self.env_holders.add(name)
                opened = self.opened_path(node.value)
                if opened is not None:
                    self.opened[name] = opened
                    continue
                path = self.path_of(node.value)
                if path is not None:
                    self.paths[name] = path
            elif isinstance(node, ast.With | ast.AsyncWith):
                for item in node.items:
                    opened = self.opened_path(item.context_expr)
                    if opened is not None and isinstance(item.optional_vars, ast.Name):
                        self.opened[item.optional_vars.id] = opened

    def executed_file(self, node: ast.AST | None) -> str | None:
        """The local file whose text exec or compile runs: `f.read()` of an opened path,
        directly or through compile()."""
        if isinstance(node, ast.Call) and self.dotted(node.func) in ("compile",
                                                                    "builtins.compile"):
            node = node.args[0] if node.args else None
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "read"):
            return None
        path = self.opened_path(node.func.value)
        return path or None

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
        """os.environ, or a whole copy of it: dict(os.environ), os.environ.copy(),
        {**os.environ}. Copies alone are not reported (they are how a child process gets
        its environment); they count only where os.environ itself would."""
        if self.dotted(node) == "os.environ":
            return True
        if isinstance(node, ast.Call):
            if self.dotted(node.func) in ("dict", "list", "sorted") and node.args and (
                    self.dotted(node.args[0]) == "os.environ"):
                return True
            return isinstance(node.func, ast.Attribute) and node.func.attr == "copy" and (
                self.dotted(node.func.value) == "os.environ")
        return isinstance(node, ast.Dict) and any(
            k is None and self.dotted(v) == "os.environ" for k, v in zip(node.keys,
                                                                       node.values,
                                                                       strict=True))

    def holds_environ(self, node: ast.AST | None, depth: int = 0) -> bool:
        """os.environ or a whole copy of it, a variable bound to one, or a dict, list,
        tuple or dict() call with one among its values: `{"env": dict(os.environ)}`."""
        if node is None or depth > 8:
            return False
        if self.is_environ(node) or (isinstance(node, ast.Name)
                                     and node.id in self.env_holders):
            return True
        if isinstance(node, ast.Dict):
            return any(self.holds_environ(v, depth + 1) for v in node.values)
        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return any(self.holds_environ(e, depth + 1) for e in node.elts)
        if isinstance(node, ast.Starred):
            return self.holds_environ(node.value, depth + 1)
        if isinstance(node, ast.Call) and self.dotted(node.func) == "dict":
            return any(self.holds_environ(v, depth + 1)
                       for v in [*node.args, *(k.value for k in node.keywords)])
        return False

    def sends(self, name: str) -> bool:
        """A call that sends data over the network: a function of a network module."""
        return any(name.startswith(candidate + ".") for candidate in NETWORK_MODULES)

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
            self.result.imports.append((alias.name, 0))
            if alias.name in ("subprocess", "pty"):
                self.hit("BS-PRC-001", node, [f"imports {alias.name}"])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            full = f"{module}.{alias.name}" if module else alias.name
            self.aliases[alias.asname or alias.name] = full
            self.network_module(full, node)
            self.network_module(module, node)
            self.result.imports.append((full, node.level))
        self.result.imports.append((module, node.level))
        if module in ("subprocess", "pty"):
            self.hit("BS-PRC-001", node, [f"imports from {module}"])

    # Calls and values --------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        name = self.dotted(node.func) or ""
        first = node.args[0] if node.args else None
        if name.startswith(PROCESS_CALLS):
            self.hit("BS-PRC-001", node, [f"calls {name}"])
            command = self.command(name, node)
            if command:
                region = self.region(node)
                self.result.snippets.append(Snippet("shell", command, region,
                                                    f"{name} command at line {region.line}"))
        elif name in ("exec", "eval", "compile", "builtins.exec", "builtins.eval") and (
                name not in self.defined):
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                decoded = any(
                    isinstance(n, ast.Call) and (self.dotted(n.func) or "").startswith(
                        DECODE_CALLS)
                    for n in ast.walk(node))
                found = self.hit("BS-EN-003" if decoded else "BS-DE-006", node,
                                 [f"{name} runs decoded data" if decoded else f"calls {name}"])
                local = None if decoded else self.executed_file(first)
                if found is not None and local:
                    # Running a file of the package: analyse that file instead, if it is
                    # in the scan (decided by the scanner).
                    self.result.hits.remove(found)
                    found.via.append(f"runs the code of {local}")
                    self.result.exec_files.append((local, found))
        values = [*node.args, *(k.value for k in node.keywords)]
        if name in ENV_SERIALIZERS and any(self.is_environ(a) for a in node.args):
            self.hit("BS-ENV-001", node, [f"os.environ passed to {name}"])
        elif (name in ENV_SERIALIZERS or self.sends(name)) and any(
                self.holds_environ(v) for v in values):
            how = "serialised by" if name in ENV_SERIALIZERS else "sent with"
            self.hit("BS-ENV-001", node, [f"os.environ, held in a value, {how} {name}"])
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("items", "keys",
                                                                       "values") and (
                self.is_environ(node.func.value)):
            self.hit("BS-ENV-001", node, [f"os.environ.{node.func.attr}()"])
        self.generic_visit(node)

    def word(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return "python" if self.dotted(node) == "sys.executable" else None

    def command(self, name: str, node: ast.Call) -> str | None:
        """The command line a process call runs, when it is written out literally."""
        if name in ARGV_CALLS or name in EXECL_CALLS:
            words = [self.word(a) for a in node.args[1 if name in EXECL_CALLS else 0:]]
            return command_line(words) if words and None not in words else None
        first = node.args[0] if node.args else next(
            (k.value for k in node.keywords if k.arg in ("args", "cmd", "command")), None)
        if first is None or not (name in SHELL_CALLS or name.startswith("subprocess.")):
            return None
        if isinstance(first, ast.List | ast.Tuple):
            words = [self.word(e) for e in first.elts]
            return command_line(words) if words and None not in words else None
        return self.word(first)

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
            self.prepare(tree)
            self.visit(tree)
        except RecursionError:
            self.result.notes.append("The code is nested too deeply to analyse fully; "
                                     "rules ran on the outer levels only.")
        self.result.hits.extend(packed_code(self.text, self.positions))
        return self.result


def analyze_python(text: str) -> PyResult:
    return _Analysis(text).run()

"""Scan files or pasted text and build a report.

A scan has three parts. Inventory finds entry points: things that run without anyone
choosing to run them, such as npm install scripts or Python .pth lines. The analyzers
then read the code those entry points run, following local JavaScript imports, and the
code embedded in them (`node -e`, `python -c`, PowerShell command lines). Finally,
findings reachable from one entry point are correlated: reading secrets and talking to
the network from the same entry point is reported on its own.

PowerShell files are analysed wherever they are, as in Bomb Squad 1. JavaScript, Python
and shell files are analysed when an entry point reaches them or when they are named on
the command line, so ordinary application code does not drown the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from bombsquad import __version__
from bombsquad.catalogue import ALL_RULES
from bombsquad.code.common import CodeHit, Snippet, clip, hidden_characters, whitespace_padding
from bombsquad.code.javascript import analyze_javascript
from bombsquad.code.python import analyze_python
from bombsquad.code.shell import analyze_shell
from bombsquad.discovery import LANGUAGE_BY_SUFFIX, Discovery
from bombsquad.inventory import discover, is_detected
from bombsquad.model import EntryPoint, FileResult, Finding, Region, ScanReport
from bombsquad.powershell.analyze import Source, analyze_tagged
from bombsquad.sources import (
    POWERSHELL_SUFFIXES,
    InputError,
    collect_files,
    display_path,
    read_source,
)
from bombsquad.textpos import Positions

STDIN_PATH = "<stdin>"
MAX_IMPORT_DEPTH = 5
MAX_FOLLOWED_FILES = 500
MAX_SNIPPET_DEPTH = 3
JS_RESOLVE_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")

# Files whose text is checked for hidden characters and whitespace padding.
TEXT_SUFFIXES = frozenset({
    *LANGUAGE_BY_SUFFIX, ".psd1", ".json", ".jsonc", ".toml", ".yml", ".yaml", ".cfg", ".ini",
    ".pth", ".gyp", ".md", ".txt", ".zsh", ".fish", ".cmd", ".bat", ".rb", ".go", ".rs",
    ".java", ".kt", ".cs", ".php", ".lua", ".vue", ".svelte", ".html", ".css",
})
TEXT_NAMES = frozenset({"makefile", "dockerfile", "justfile", ".npmrc", ".yarnrc"})

SECRET_RULES = frozenset({"BS-CR-001", "BS-ENV-001"})
NETWORK_RULES = frozenset({"BS-NET-001", "BS-NET-002", "BS-NET-003"})


@dataclass
class _File:
    """One file read from disk, with what its analyzer found."""

    path: Path
    shown: str
    text: str
    language: str
    hits: list[CodeHit] = field(default_factory=list)
    snippets: list[Snippet] = field(default_factory=list)
    imports: list[Path] = field(default_factory=list)
    entries: list[EntryPoint] = field(default_factory=list)  # entry points that reach it
    named: bool = False  # named on the command line


@dataclass
class _Tagged:
    finding: Finding
    entries: tuple[EntryPoint, ...]
    unit: str  # correlation unit for findings no entry point reaches


class _Scan:
    def __init__(self) -> None:
        self.results: dict[str, FileResult] = {}
        self.files: dict[Path, _File] = {}
        self.texts: dict[Path, str] = {}
        self.encodings: dict[str, str] = {}  # shown path -> encoding
        self.found = Discovery()
        self.tagged: list[_Tagged] = []
        self.powershell: list[Source] = []
        self.files_read = 0
        self.roots: list[Path] = []

    # Reading -----------------------------------------------------------------------------

    def read(self, path: Path) -> str | None:
        key = path.resolve()
        if key in self.texts:
            return self.texts[key]
        shown = display_path(path)
        try:
            text, encoding = read_source(path)
        except (InputError, OSError) as exc:
            self.result(shown, LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), "unknown"),
                        "unreadable").notes.append(str(exc))
            return None
        self.texts[key] = text
        self.encodings[shown] = encoding
        self.files_read += 1
        return text

    def result(self, shown: str, language: str, status: str = "analysed") -> FileResult:
        if shown not in self.results:
            self.results[shown] = FileResult(shown, language, status,
                                             encoding=self.encodings.get(shown))
        return self.results[shown]

    def inside_roots(self, path: Path) -> bool:
        for root in self.roots:
            try:
                path.relative_to(root)
                return True
            except ValueError:
                continue
        return False

    # Analysis ----------------------------------------------------------------------------

    def analyse_file(self, path: Path, language: str, named: bool = False) -> _File | None:
        key = path.resolve()
        if key in self.files:
            self.files[key].named |= named
            return self.files[key]
        text = self.read(key)
        if text is None:
            return None
        item = _File(key, display_path(key), text, language, named=named)
        self.files[key] = item
        self.result(item.shown, language)
        if language == "javascript":
            js = analyze_javascript(text, item.shown)
            item.hits = js.hits
            item.imports = [p for p in (self.resolve_import(key, spec)
                                        for spec in js.relative_imports) if p]
            self.results[item.shown].notes.extend(js.notes)
        elif language == "python":
            py = analyze_python(text)
            item.hits = py.hits
            self.results[item.shown].notes.extend(py.notes)
        elif language == "shell":
            sh = analyze_shell(text)
            item.hits, item.snippets = sh.hits, sh.snippets
            self.results[item.shown].notes.extend(sh.notes)
        return item

    def resolve_import(self, importer: Path, spec: str) -> Path | None:
        base = (importer.parent / spec.split("?")[0]).resolve()
        candidates = [base, *(base.with_name(base.name + s) for s in JS_RESOLVE_SUFFIXES),
                      *(base / f"index{s}" for s in JS_RESOLVE_SUFFIXES)]
        for candidate in candidates:
            if candidate.is_file() and candidate.suffix.lower() in JS_RESOLVE_SUFFIXES and (
                    self.inside_roots(candidate)):
                return candidate
        return None

    def follow(self, entry: EntryPoint, start: Path, language: str) -> None:
        """Analyse an entry point's target and the local files it imports."""
        frontier = [(start, language, 0)]
        visited: set[Path] = set()
        while frontier:
            path, lang, depth = frontier.pop(0)
            if path in visited:
                continue
            visited.add(path)
            if lang == "powershell":
                self.add_powershell_file(path, entry)
                continue
            if len(self.files) >= MAX_FOLLOWED_FILES:
                self.found.notes.append((entry.path, f"Stopped following imports after "
                                                     f"{MAX_FOLLOWED_FILES} files."))
                return
            item = self.analyse_file(path, lang)
            if item is None:
                continue
            if entry not in item.entries:
                item.entries.append(entry)
            if item.shown not in entry.targets:
                entry.targets.append(item.shown)
            if depth >= MAX_IMPORT_DEPTH:
                if item.imports:
                    self.results[item.shown].notes.append(
                        f"Imports more than {MAX_IMPORT_DEPTH} levels from {entry.path} "
                        "were not followed.")
                continue
            frontier.extend((p, "javascript", depth + 1) for p in item.imports)

    def add_powershell_file(self, path: Path, entry: EntryPoint | None) -> None:
        shown = display_path(path)
        for i, source in enumerate(self.powershell):
            if source.path == shown and source.anchor is None:
                entries = source.tag if entry is None or entry in source.tag else (
                    (*source.tag, entry))
                self.powershell[i] = Source(shown, source.text, tag=entries)
                return
        text = self.read(path)
        if text is None:
            return
        self.result(shown, "powershell")
        self.powershell.append(Source(shown, text, tag=(entry,) if entry else ()))

    # Snippets ----------------------------------------------------------------------------

    def snippet(self, shown: str, snippet: Snippet, entries: tuple[EntryPoint, ...],
                via: tuple[str, ...], anchor: Region | None, depth: int) -> None:
        """Analyse code embedded in a file. Findings point at where it is embedded: the
        exact line when the snippet is a verbatim block of the file, else its anchor."""
        anchor = anchor or snippet.region
        via = (*via, snippet.origin)

        def place(region: Region) -> Region:
            if snippet.offset is None:
                return anchor
            lines, columns = snippet.offset
            return Region(region.line + lines, region.column + columns,
                          region.end_line + lines, region.end_column + columns)

        self.result(shown, "unknown")
        if snippet.language == "powershell":
            self.powershell.append(Source(shown, snippet.text, anchor, via, entries))
            return
        snippets: list[Snippet] = []
        if snippet.language == "javascript":
            js = analyze_javascript(snippet.text, "snippet.js")
            hits = js.hits
            if js.relative_imports:
                self.results[shown].notes.append(
                    f"Code embedded at line {anchor.line} loads local files "
                    f"({', '.join(sorted(set(js.relative_imports)))}); they were not followed.")
        elif snippet.language == "python":
            hits = analyze_python(snippet.text).hits
        else:
            sh = analyze_shell(snippet.text)
            hits, snippets = sh.hits, sh.snippets
        for h in hits:
            self.add(h, shown, entries, via, place(h.region), unit=shown)
        if snippets and depth >= MAX_SNIPPET_DEPTH:
            self.results[shown].notes.append(
                f"Code nested more than {MAX_SNIPPET_DEPTH} levels deep at line {anchor.line} "
                "was not analysed.")
            return
        for inner in snippets:
            self.snippet(shown, inner, entries, via, place(inner.region), depth + 1)

    # Findings ----------------------------------------------------------------------------

    def add(self, hit: CodeHit, shown: str, entries: tuple[EntryPoint, ...],
            via: tuple[str, ...], anchor: Region | None, unit: str) -> None:
        rule = ALL_RULES[hit.rule_id]
        finding = Finding(rule, shown, anchor or hit.region, hit.evidence, hit.level or rule.level,
                          [*via, *hit.via], list(hit.limitations))
        self.tagged.append(_Tagged(finding, entries, unit))

    def text_rules(self, path: Path) -> None:
        key = path.resolve()
        text = self.texts.get(key)
        if text is None:
            return
        positions = Positions(text)
        hits = [*hidden_characters(text, positions), *whitespace_padding(text, positions)]
        if not hits:
            return
        shown = display_path(key)
        item = self.files.get(key)
        entries = tuple(item.entries) if item else ()
        for source in self.powershell:
            if source.path == shown and source.anchor is None:
                entries = tuple(source.tag)
        language = item.language if item else LANGUAGE_BY_SUFFIX.get(key.suffix.lower(), "text")
        self.result(shown, language)
        via = (entries[0].describe(),) if entries and entries[0].path != shown else ()
        for h in hits:
            self.add(h, shown, entries, via, None, unit=shown)

    def correlate(self) -> list[Finding]:
        """One BS-EX-001 per entry point (or unreached file) that reads secrets and has
        network access somewhere in the code it runs.

        GitHub Actions entry points are left out: workflows and actions use tokens and the
        network by design, and the official toolkit reads the OIDC token variables. There,
        BS-GHA-006 looks at secrets sent from a step's own script instead."""
        units: dict[object, list[Finding]] = {}
        anchors: dict[object, EntryPoint | None] = {}
        for t in self.tagged:
            if t.entries:
                if all(e.surface == "github-actions" for e in t.entries):
                    continue
                for entry in t.entries:
                    if entry.surface == "github-actions":
                        continue
                    units.setdefault(id(entry), []).append(t.finding)
                    anchors[id(entry)] = entry
            else:
                units.setdefault(t.unit, []).append(t.finding)
                anchors.setdefault(t.unit, None)
        out: list[Finding] = []
        rule = ALL_RULES["BS-EX-001"]
        for key, findings in units.items():
            secrets = [f for f in findings if f.rule.id in SECRET_RULES]
            network = [f for f in findings if f.rule.id in NETWORK_RULES]
            if not secrets or not network:
                continue
            entry = anchors[key]
            secret, net = secrets[0], network[0]
            via = [f"collects: {secret.rule.title.lower()} at {secret.path}:"
                   f"{secret.region.line} ({clip(secret.evidence)[:120]})",
                   f"network: {net.rule.title.lower()} at {net.path}:{net.region.line} "
                   f"({clip(net.evidence)[:120]})"]
            if entry is not None:
                out.append(Finding(rule, entry.path, entry.region, clip(entry.runs), rule.level,
                                   [entry.describe(), *via]))
            else:
                out.append(Finding(rule, secret.path, secret.region, secret.evidence,
                                   rule.level, via, ["No entry point was found that runs this "
                                                     "file; it was scanned because it was "
                                                     "named or is PowerShell."]))
        return out

    # Whole scan --------------------------------------------------------------------------

    def run(self, paths: list[Path], stdin_text: str | None) -> ScanReport:
        self.roots = [p.resolve() if p.is_dir() else p.resolve().parent for p in paths
                      if p.exists()]
        files = collect_files(paths)
        for path, named in files:
            suffix = path.suffix.lower()
            if suffix in POWERSHELL_SUFFIXES:
                self.add_powershell_file(path, None)
            elif is_detected(path):
                text = self.read(path)
                if text is not None:
                    discover(path, display_path(path), text, self.found, display_path)
            elif named and suffix in LANGUAGE_BY_SUFFIX:
                self.analyse_file(path, LANGUAGE_BY_SUFFIX[suffix], named=True)
            elif named and (suffix in TEXT_SUFFIXES or path.name.lower() in TEXT_NAMES):
                if self.read(path) is not None:
                    self.result(display_path(path), "text").notes.append(
                        "Checked for hidden characters and whitespace padding only.")
            elif named:
                shown = display_path(path)
                self.results[shown] = FileResult(
                    shown, "unknown", "not_analysed",
                    notes=["Not a file type Bomb Squad analyses, and no entry point runs it."])

        for target in self.found.targets:
            self.follow(target.entry, target.path, target.language)
        for entry in self.found.entry_points:
            self.result(entry.path, "manifest")

        # Hits found by the analyzers, in files that were read whole.
        for item in self.files.values():
            entries = tuple(item.entries)
            via = (entries[0].describe(),) if entries and entries[0].path != item.shown else ()
            for h in item.hits:
                self.add(h, item.shown, entries, via, None, unit=item.shown)
            for s in item.snippets:
                self.snippet(item.shown, s, entries, via, None, 1)
        for shown, hit, entry in self.found.hits:
            self.add(hit, shown, (entry,) if entry else (), (), None, unit=shown)
        for shown, s, entry in self.found.snippets:
            self.snippet(shown, s, (entry,), (entry.describe(),), None, 1)
        for shown, note in self.found.notes:
            self.result(shown, "manifest").notes.append(note)

        for path, _ in files:
            if path.suffix.lower() in TEXT_SUFFIXES or path.name.lower() in TEXT_NAMES or (
                    path.resolve() in self.files):
                if path.resolve() not in self.texts:
                    try:
                        text, encoding = read_source(path)
                    except (InputError, OSError):
                        continue  # too large or unreadable; not part of any entry point
                    self.texts[path.resolve()] = text
                    self.encodings[display_path(path)] = encoding
                    self.files_read += 1
                self.text_rules(path)

        if stdin_text is not None:
            self.results[STDIN_PATH] = FileResult(STDIN_PATH, "powershell", "analysed",
                                                  encoding="utf-8")
            self.powershell.append(Source(STDIN_PATH, stdin_text, tag=()))

        parser_info: dict | None = None
        if self.powershell:
            parser_info, ps_findings = analyze_tagged(self.powershell, self.results)
            for finding, entries in ps_findings:
                entries = tuple(entries or ())
                first = entries[0].describe() if entries else None
                if first and entries[0].path != finding.path and finding.via[:1] != [first]:
                    finding.via.insert(0, first)
                self.tagged.append(_Tagged(finding, entries, finding.path))
            if parser_info.get("edition") == "Desktop":
                for r in self.results.values():
                    if r.parse_errors:
                        r.notes.append(
                            "Parsed with Windows PowerShell 5.1, which rejects PowerShell 7 "
                            "syntax such as && and ternaries. Install pwsh to parse it as "
                            "PowerShell 7.")

        findings = _dedupe([t.finding for t in self.tagged]) + self.correlate()
        if self.found.expressions:
            for f in findings:
                f.evidence = _restore(f.evidence, self.found.expressions)
                f.via = [_restore(step, self.found.expressions) for step in f.via]
        findings.sort(key=lambda f: (f.path, f.region.line, f.region.column, f.rule.id))
        for f in findings:
            if f.path not in self.results:
                self.result(f.path, "unknown")
        ordered = sorted(self.results.values(), key=lambda r: r.path)
        return ScanReport(__version__, ordered, findings,
                          {"name": "PowerShell", **parser_info} if parser_info else None,
                          self.found.entry_points, self.files_read)


def _restore(text: str, expressions: dict[str, str]) -> str:
    """Put back the ${{ }} expressions that placeholders stood in for while parsing."""
    if "_BS" not in text:
        return text
    for token in sorted((t for t in expressions if t in text), key=len, reverse=True):
        text = text.replace(token, expressions[token])
    return text


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop exact repeats: the same rule at the same place with the same evidence."""
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule.id, f.path, f.region, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def scan(paths: list[Path] | None = None, stdin_text: str | None = None) -> ScanReport:
    """Scan files and directories, and optionally pasted PowerShell."""
    return _Scan().run(paths or [], stdin_text)


__all__ = ["STDIN_PATH", "scan"]

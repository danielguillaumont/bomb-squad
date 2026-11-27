"""Command line: `bombsquad scan`, `bombsquad diff`, `bombsquad gate` and `bombsquad rules`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from bombsquad import __version__
from bombsquad.catalogue import ALL_RULES as RULES
from bombsquad.model import Level
from bombsquad.powershell.parser import ParserFailed, ParserUnavailable
from bombsquad.sarif import to_sarif
from bombsquad.scan import scan
from bombsquad.sources import InputError, decode
from bombsquad.text_report import render, render_diff

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bombsquad",
        description="Find what runs before anyone chooses to run it. "
                    "Static analysis only: nothing scanned is executed.",
    )
    parser.add_argument("--version", action="version", version=f"bombsquad {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="scan files, directories, or - for pasted text")
    scan_cmd.add_argument("paths", nargs="+", help="files or directories; - reads stdin")
    scan_cmd.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    scan_cmd.add_argument("--output", "-o", type=Path, help="write the report to this file")
    scan_cmd.add_argument("--package", action="store_true",
                          help="the folder is a published package: findings that only "
                               "workflows, git hooks, editor or agent settings reach are "
                               "reported at info, since installing does not run them")
    scan_cmd.add_argument(
        "--fail-on", choices=("high", "review", "info", "never"), default="never",
        help="exit with status 1 when a finding at this level or above is reported",
    )

    diff_cmd = sub.add_parser(
        "diff", help="what a new version gains: npm:<name>@<old>..<new>, "
                     "pypi:<name>@<old>..<new>, or two folders or archives")
    diff_cmd.add_argument("subject", nargs="+", metavar="SPEC_OR_PATHS")
    diff_cmd.add_argument("--format", choices=("text", "json"), default="text")
    diff_cmd.add_argument("--source", action="store_true",
                          help="also compare the new version with its GitHub repository at "
                               "the release tag")
    diff_cmd.add_argument("--record", type=Path, metavar="FILE",
                          help="keep release tags' commits in FILE and report tags that moved "
                               "since they were recorded (implies --source)")
    diff_cmd.add_argument("--output", "-o", type=Path, help="write the report to this file")
    diff_cmd.add_argument(
        "--fail-on", choices=("high", "review", "info", "never"), default="never",
        help="exit with status 1 when a new finding or signal is at this level or above",
    )

    gate_cmd = sub.add_parser(
        "gate", help="what a pull request newly runs: compare its base and head folders, and "
                     "review each dependency version its lockfiles newly pin")
    gate_cmd.add_argument("base", type=Path, help="the pull request's base, checked out")
    gate_cmd.add_argument("head", type=Path, help="the pull request's head, checked out")
    gate_cmd.add_argument("--format", choices=("markdown", "text", "json"), default="text")
    gate_cmd.add_argument("--output", "-o", type=Path, help="write the report to this file")
    gate_cmd.add_argument("--sarif", type=Path, metavar="FILE",
                          help="also write the repository's new findings as SARIF")
    gate_cmd.add_argument("--markdown", type=Path, metavar="FILE",
                          help="also write the report as a pull request comment")
    gate_cmd.add_argument("--json", type=Path, metavar="FILE",
                          help="also write the report as JSON")
    gate_cmd.add_argument("--max-packages", type=int, default=25, metavar="N",
                          help="review at most N new dependency versions (default 25, direct "
                               "dependencies first)")
    gate_cmd.add_argument("--source", action="store_true",
                          help="also compare each new dependency version with its GitHub "
                               "source at the release tag")
    gate_cmd.add_argument(
        "--fail-on", choices=("high", "review", "info", "never"), default="never",
        help="exit with status 1 when a new finding or signal is at this level or above",
    )

    sub.add_parser("rules", help="list the rules")
    return parser


def _write(text: str, output: Path | None) -> None:
    if output:
        output.write_text(text, encoding="utf-8", newline="\n")
        return
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    sys.stdout.write(text)


def _write_json(value: object, output: Path | None) -> None:
    """A file gets UTF-8. Standard output gets ASCII with JSON escapes: piped, it is
    encoded in the console's code page, which on Windows cannot hold every character and
    would make the JSON invalid."""
    _write(json.dumps(value, indent=2, ensure_ascii=output is None) + "\n", output)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.command == "rules":
        for rule in sorted(RULES.values(), key=lambda r: r.id):
            print(f"{rule.id:<11} {rule.level.value:<6} {rule.family:<18} {rule.title}")
        return EXIT_OK

    if args.command == "diff":
        return _diff(args)
    if args.command == "gate":
        return _gate(args)

    paths = [Path(p) for p in args.paths if p != "-"]
    stdin_text = decode(sys.stdin.buffer.read())[0] if "-" in args.paths else None
    try:
        report = scan(paths, stdin_text, package=args.package)
    except (InputError, ParserUnavailable, ParserFailed) as exc:
        print(f"bombsquad: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.format == "json":
        _write_json(report.to_dict(), args.output)
    elif args.format == "sarif":
        _write_json(to_sarif(report), args.output)
    else:
        _write(render(report), args.output)

    if args.fail_on != "never":
        threshold = Level(args.fail_on).rank
        if any(f.level.rank >= threshold for f in report.findings):
            return EXIT_FINDINGS
    return EXIT_OK


def _diff(args) -> int:
    from bombsquad.archive import ArchiveError
    from bombsquad.diff import diff_paths, diff_registry
    from bombsquad.registry import FetchError

    try:
        if len(args.subject) == 1:
            report = diff_registry(args.subject[0], source=args.source, record=args.record)
        elif args.source or args.record:
            raise ValueError("--source and --record need an npm: or pypi: spec")
        elif len(args.subject) == 2:
            report = diff_paths(Path(args.subject[0]), Path(args.subject[1]))
        else:
            raise ValueError("give one npm:/pypi: spec, or an old and a new path")
    except (ValueError, OSError, FetchError, ArchiveError, InputError, ParserFailed,
            ParserUnavailable) as exc:
        print(f"bombsquad: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.format == "json":
        _write_json(report.to_dict(), args.output)
    else:
        _write(render_diff(report), args.output)
    if args.fail_on != "never":
        highest = report.highest_level()
        if highest is not None and highest.rank >= Level(args.fail_on).rank:
            return EXIT_FINDINGS
    return EXIT_OK


def _gate(args) -> int:
    from bombsquad.gate import gate, gate_sarif_report, render_markdown, render_text

    try:
        report = gate(args.base, args.head, max_packages=max(0, args.max_packages),
                      source=args.source)
    except (ValueError, OSError, InputError, ParserFailed, ParserUnavailable) as exc:
        print(f"bombsquad: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.format == "json":
        _write_json(report.to_dict(), args.output)
    elif args.format == "markdown":
        _write(render_markdown(report), args.output)
    else:
        _write(render_text(report), args.output)
    if args.markdown:
        args.markdown.write_text(render_markdown(report), encoding="utf-8", newline="\n")
    if args.json:
        args.json.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n",
                             encoding="utf-8", newline="\n")
    if args.sarif:
        sarif = to_sarif(gate_sarif_report(report))
        args.sarif.write_text(json.dumps(sarif, indent=2, ensure_ascii=False) + "\n",
                              encoding="utf-8", newline="\n")
    if args.fail_on != "never":
        highest = report.highest_level()
        if highest is not None and highest.rank >= Level(args.fail_on).rank:
            return EXIT_FINDINGS
    return EXIT_OK

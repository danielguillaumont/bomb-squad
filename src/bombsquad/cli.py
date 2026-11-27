"""Command line: `bombsquad scan`, `bombsquad diff` and `bombsquad rules`."""

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

    sub.add_parser("rules", help="list the rules")
    return parser


def _write(text: str, output: Path | None) -> None:
    if output:
        output.write_text(text, encoding="utf-8", newline="\n")
        return
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    sys.stdout.write(text)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    if args.command == "rules":
        for rule in sorted(RULES.values(), key=lambda r: r.id):
            print(f"{rule.id:<11} {rule.level.value:<6} {rule.family:<18} {rule.title}")
        return EXIT_OK

    if args.command == "diff":
        return _diff(args)

    paths = [Path(p) for p in args.paths if p != "-"]
    stdin_text = decode(sys.stdin.buffer.read())[0] if "-" in args.paths else None
    try:
        report = scan(paths, stdin_text)
    except (InputError, ParserUnavailable, ParserFailed) as exc:
        print(f"bombsquad: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.format == "json":
        _write(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n", args.output)
    elif args.format == "sarif":
        _write(json.dumps(to_sarif(report), indent=2, ensure_ascii=False) + "\n", args.output)
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
        _write(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n", args.output)
    else:
        _write(render_diff(report), args.output)
    if args.fail_on != "never":
        highest = report.highest_level()
        if highest is not None and highest.rank >= Level(args.fail_on).rank:
            return EXIT_FINDINGS
    return EXIT_OK

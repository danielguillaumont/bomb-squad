"""Command line: `bombsquad scan` and `bombsquad rules`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from bombsquad import __version__
from bombsquad.model import Level
from bombsquad.powershell.parser import ParserFailed, ParserUnavailable
from bombsquad.powershell.rules import RULES
from bombsquad.sarif import to_sarif
from bombsquad.scan import scan
from bombsquad.sources import InputError, decode
from bombsquad.text_report import render

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

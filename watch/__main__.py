"""`python -m watch run`: diff the new releases of the pinned popular lists in a window."""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from benchmark import benign
from bombsquad import __version__
from bombsquad.registry import FetchError, http_get
from watch import daily


def _moment(text: str) -> datetime:
    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _run(args) -> int:
    until = _moment(args.until) if args.until else datetime.now(UTC).replace(
        minute=0, second=0, microsecond=0)
    since = _moment(args.since) if args.since else until - timedelta(days=1)
    if since >= until:
        raise SystemExit("--since must be before --until")
    with TemporaryDirectory(prefix="watch-lists-") as work:
        pypi = (benign.pypi_names_from(args.pypi_list.read_text(encoding="utf-8"))
                if args.pypi_list else benign.pypi_popular(http_get))
        lists = {"npm": benign.npm_popular(http_get, Path(work))[:args.top],
                 "pypi": pypi[:args.top]}
    packages = [(e, n) for e, names in lists.items() for n in names]
    meta = {"since": since.isoformat(), "until": until.isoformat(), "bombsquad": __version__,
            "top": args.top, "packages": len(packages),
            "lists": f"npm {benign.NPM_LIST_PACKAGE}@{benign.NPM_LIST_VERSION}, PyPI "
                     f"{benign.PYPI_LIST_REPO}@{benign.PYPI_LIST_COMMIT[:12]}"}

    def releases(package):
        ecosystem, name = package
        try:
            return daily.new_releases(ecosystem, name, since, until, http_get)
        except (FetchError, ValueError) as exc:
            return [{"ecosystem": ecosystem, "name": name, "status": "error",
                     "diff": {"error": f"metadata: {str(exc)[:200]}"}, "version": "?",
                     "previous": None, "published": None}]

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        found = [r for rs in pool.map(releases, packages) for r in rs]
        rows = list(pool.map(lambda r: r if r.get("status") else daily.check(r), found))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as out:
        out.write(json.dumps({"meta": meta}) + "\n")
        for row in rows:
            out.write(json.dumps(row) + "\n")
    text = daily.markdown(meta, rows)
    if args.markdown:
        args.markdown.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m watch")
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="diff the new releases in a window")
    r.add_argument("--since", help="ISO time; default a day before --until")
    r.add_argument("--until", help="ISO time; default the start of this hour (UTC)")
    r.add_argument("--top", type=int, default=500, help="packages per ecosystem list")
    r.add_argument("--pypi-list", type=Path,
                   help=f"{benign.PYPI_LIST_FILE} at {benign.PYPI_LIST_REPO} commit "
                        f"{benign.PYPI_LIST_COMMIT[:12]}, already downloaded")
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--output", "-o", type=Path, required=True)
    r.add_argument("--markdown", type=Path)
    args = parser.parse_args(argv)
    return {"run": _run}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())

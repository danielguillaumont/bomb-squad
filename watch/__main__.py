"""`python -m watch`: diff the new releases of the pinned popular lists in a window (`run`),
record a person's review of a queued release (`review`), a report and its outcome (`report`,
`outcome`), check a ledger (`verify`), and build the site and feed from the ledgers (`site`).
"""

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
from watch import daily, ledger, review, site


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


def _review(args) -> int:
    ecosystem, name, version = review.parse_release(args.release)
    row = review.queued_row(args.queue, ecosystem, name, version)
    diff = json.loads(args.diff.read_text(encoding="utf-8")) if args.diff else None
    entry = ledger.append(args.log, review.flag_record(row, diff, args.outcome, args.note,
                                                       args.reviewer))
    print(f"flag log entry {entry['seq']}: {entry['release']} {entry['outcome']} "
          f"({entry['hash']})")
    return 0


def _report(args) -> int:
    entry = ledger.append(args.record, review.report_record(
        ledger.verify(args.flags), args.flag, args.to, args.reference))
    print(f"defusal record entry {entry['seq']}: {entry['release']} reported to "
          f"{entry['reported_to']} ({entry['hash']})")
    return 0


def _outcome(args) -> int:
    entry = ledger.append(args.record, review.outcome_record(
        ledger.verify(args.record), args.report, args.outcome, args.link, args.note))
    print(f"defusal record entry {entry['seq']}: report {entry['report']} {entry['outcome']} "
          f"({entry['hash']})")
    return 0


def _verify(args) -> int:
    entries = ledger.verify(args.ledger)
    for kept in args.head:
        seq, _, digest = kept.partition(":")
        if not seq.isdigit() or len(digest) != 64:
            raise SystemExit(f"--head takes SEQ:HASH, not {kept!r}")
        ledger.check_head(entries, int(seq), digest)
    seq, digest = ledger.head(entries)
    print(f"{args.ledger.name}: {seq} entries, head {seq}:{digest}")
    return 0


def _site(args) -> int:
    built = site.build(args.flags, args.defusals, args.out, args.base_url, datetime.now(UTC))
    print(f"{built['listed']} listed updates and {built['reports']} reports written to "
          f"{args.out}")
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

    v = sub.add_parser("review", help="record a person's review of a queued release")
    v.add_argument("release", help="npm:name@version or pypi:name@version")
    v.add_argument("--queue", type=Path, required=True, help="the run's results file")
    v.add_argument("--diff", type=Path,
                   help="`bombsquad diff … --format json` of the update, as reviewed")
    v.add_argument("--outcome", choices=review.OUTCOMES, required=True)
    v.add_argument("--note", required=True, help="what the review found")
    v.add_argument("--reviewer", required=True)
    v.add_argument("--log", type=Path, required=True, help="the flag log")

    p = sub.add_parser("report", help="record a report sent about a listed release")
    p.add_argument("--flags", type=Path, required=True, help="the flag log")
    p.add_argument("--flag", type=int, required=True, help="the listed release's entry")
    p.add_argument("--to", choices=review.REPORTED_TO, required=True)
    p.add_argument("--reference", required=True, help="the report's https link")
    p.add_argument("--record", type=Path, required=True, help="the defusal record")

    o = sub.add_parser("outcome", help="record what became of a report")
    o.add_argument("--record", type=Path, required=True, help="the defusal record")
    o.add_argument("--report", type=int, required=True, help="the report's entry")
    o.add_argument("--outcome", choices=review.REPORT_OUTCOMES, required=True)
    o.add_argument("--link", help="the https link that shows the outcome")
    o.add_argument("--note", default="")

    c = sub.add_parser("verify", help="check a ledger's chain, and heads kept from it")
    c.add_argument("ledger", type=Path)
    c.add_argument("--head", action="append", default=[], metavar="SEQ:HASH")

    s = sub.add_parser("site", help="build the site and feed from the ledgers")
    s.add_argument("--flags", type=Path, required=True)
    s.add_argument("--defusals", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--base-url", required=True, help="where the site is served, ending in /")

    args = parser.parse_args(argv)
    commands = {"run": _run, "review": _review, "report": _report, "outcome": _outcome,
                "verify": _verify, "site": _site}
    try:
        return commands[args.command](args)
    except (ledger.LedgerError, review.ReviewError, ValueError) as exc:
        print(f"watch: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

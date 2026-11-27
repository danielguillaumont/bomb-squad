"""`python -m benchmark select|run|score`. See `.github/workflows/benchmark.yml`."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime
from pathlib import Path

from benchmark import benign, samples, score, tools
from bombsquad import __version__
from bombsquad.registry import http_get


def _select(args) -> int:
    listing = args.listing.read_text(encoding="utf-8").splitlines()
    chosen = samples.select(samples.parse_listing(listing), args.per_ecosystem, args.seed,
                            date.fromisoformat(args.cutoff))
    document = {"seed": args.seed, "cutoff": args.cutoff, "per_ecosystem": args.per_ecosystem,
                "samples": [s.to_dict() for s in chosen]}
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    if args.paths:
        args.paths.write_text("".join(s.path + "\n" for s in chosen), encoding="utf-8")
    counts = {e: sum(1 for s in chosen if s.ecosystem == e) for e in samples.ECOSYSTEMS}
    print(f"selected {len(chosen)} samples: {counts}")
    return 0


def _benign_packages(args, work: Path) -> list[dict]:
    as_of = datetime.fromisoformat(args.as_of).replace(tzinfo=UTC)
    # The workflow fetches the PyPI list with its own token: unauthenticated GitHub API
    # requests from shared runners hit the rate limit.
    pypi = (benign.pypi_names_from(args.pypi_list.read_text(encoding="utf-8"))
            if args.pypi_list else benign.pypi_popular(http_get))
    lists = {"npm": benign.npm_popular(http_get, work), "pypi": pypi}
    out = []
    for ecosystem, names in lists.items():
        for name in benign.sample_names(names, args.benign_top, args.benign_per_ecosystem,
                                        args.seed, ecosystem):
            row = {"set": "benign", "ecosystem": ecosystem, "name": name}
            try:
                row["version"] = benign.release_on(ecosystem, name, as_of, http_get)
                if row["version"] is None:
                    row["prepare_error"] = f"no stable release on or before {args.as_of}"
            except (benign.FetchError, ValueError) as exc:
                row["prepare_error"] = f"metadata: {exc}"
            out.append(row)
    return out


def _evaluate(row: dict, args, sample: samples.Sample | None) -> dict:
    with tempfile.TemporaryDirectory(prefix="bench-", ignore_cleanup_errors=True) as work:
        try:
            if sample is not None:
                root, _ = samples.extract(sample, args.dataset, Path(work))
            else:
                root = benign.fetch_release(row["ecosystem"], row["name"], row["version"],
                                            Path(work, "release"), http_get)
        except Exception as exc:  # a sample that cannot be prepared is reported, not fatal
            row["prepare_error"] = f"{exc.__class__.__name__}: {str(exc)[:300]}"
            return row
        row["bombsquad"] = tools.bombsquad(root)
        row["guarddog"] = tools.guarddog(args.guarddog, row["ecosystem"], root)
    return row


def _run(args) -> int:
    selection = json.loads(args.selected.read_text(encoding="utf-8"))
    chosen = [samples.Sample(**{**s, "splits": tuple(s["splits"])})
              for s in selection["samples"]]
    meta = {
        "started": datetime.now(UTC).isoformat(timespec="seconds"),
        "bombsquad": __version__, "bombsquad_commit": os.environ.get("GITHUB_SHA"),
        "guarddog": args.guarddog_version or tools.version(args.guarddog),
        "dataset": "DataDog/malicious-software-packages-dataset",
        "dataset_commit": args.dataset_commit, "dataset_date": args.dataset_date,
        "seed": selection["seed"], "cutoff": selection["cutoff"],
        "malicious_per_ecosystem": selection["per_ecosystem"],
        "benign_lists": f"npm {benign.NPM_LIST_PACKAGE}@{benign.NPM_LIST_VERSION}, PyPI "
                        f"{benign.PYPI_LIST_REPO}@{benign.PYPI_LIST_COMMIT[:12]}",
        "benign_per_ecosystem": args.benign_per_ecosystem, "benign_top": args.benign_top,
        "benign_as_of": args.as_of,
    }
    with tempfile.TemporaryDirectory(prefix="bench-lists-") as work:
        benign_rows = _benign_packages(args, Path(work)) if args.benign_per_ecosystem else []
    jobs: list[tuple[dict, samples.Sample | None]] = [
        ({"set": "malicious", "ecosystem": s.ecosystem, "name": s.name, "version": s.version,
          "kind": s.kind, "discovered": s.discovered, "splits": list(s.splits)}, s)
        for s in chosen]
    jobs += [(row, None) for row in benign_rows]
    lock = threading.Lock()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as out:
        out.write(json.dumps({"meta": meta}) + "\n")

        def work(job):
            row, sample = job
            if not row.get("prepare_error"):
                row = _evaluate(row, args, sample)
            with lock:
                out.write(json.dumps(row) + "\n")
                out.flush()

        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            list(pool.map(work, jobs))
    print(f"evaluated {len(jobs)} packages into {args.output}")
    return 0


def _score(args) -> int:
    meta, rows = score.load(args.results)
    scores = score.score(meta, rows)
    if args.json:
        args.json.write_text(json.dumps(scores, indent=2) + "\n", encoding="utf-8")
    text = score.markdown(scores)
    if args.markdown:
        args.markdown.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmark")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("select", help="choose samples from a dataset listing")
    s.add_argument("--listing", type=Path, required=True)
    s.add_argument("--per-ecosystem", type=int, default=200)
    s.add_argument("--seed", type=int, default=2026)
    s.add_argument("--cutoff", required=True, help="ISO date the rules were frozen")
    s.add_argument("--output", "-o", type=Path, required=True)
    s.add_argument("--paths", type=Path, help="also write the sample paths, one per line")

    r = sub.add_parser("run", help="run both tools on the selected and benign packages")
    r.add_argument("--selected", type=Path, required=True)
    r.add_argument("--dataset", type=Path, required=True, help="the dataset checkout")
    r.add_argument("--dataset-commit", required=True)
    r.add_argument("--dataset-date", required=True)
    r.add_argument("--guarddog", default="guarddog")
    r.add_argument("--guarddog-version")
    r.add_argument("--benign-per-ecosystem", type=int, default=200)
    r.add_argument("--benign-top", type=int, default=1000)
    r.add_argument("--pypi-list", type=Path,
                   help=f"{benign.PYPI_LIST_FILE} at {benign.PYPI_LIST_REPO} commit "
                        f"{benign.PYPI_LIST_COMMIT[:12]}, already downloaded")
    r.add_argument("--as-of", required=True, help="ISO date: benign releases current then")
    r.add_argument("--seed", type=int, default=2026)
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--output", "-o", type=Path, required=True)

    c = sub.add_parser("score", help="compute the scores from a results file")
    c.add_argument("results", type=Path)
    c.add_argument("--json", type=Path)
    c.add_argument("--markdown", type=Path)

    args = parser.parse_args(argv)
    return {"select": _select, "run": _run, "score": _score}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())

"""`python -m benchmark select|run|score`. See `.github/workflows/benchmark.yml`."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import UTC, date, datetime
from pathlib import Path

from benchmark import benign, detonation, incidents, openssf, samples, score, tools, triage_eval
from bombsquad import __version__
from bombsquad.powershell.parser import ParserUnavailable, find_powershell
from bombsquad.registry import http_get


def _powershell() -> str:
    """The PowerShell that parses for Bomb Squad. Without one, a scan notes PowerShell
    embedded in other files as not analysed, so its findings would drop out of the scores
    with no error."""
    try:
        executable = find_powershell()
    except ParserUnavailable as exc:
        raise SystemExit(f"benchmark: {exc}") from exc
    return tools.version(executable) or executable


def _exclusions(specs: list[str]) -> list[tuple[int, int]]:
    """`SEED:COUNT` pairs: the selections of earlier runs, to leave out."""
    out = []
    for spec in specs:
        seed, _, count = spec.partition(":")
        if not (seed.isdigit() and count.isdigit()):
            raise SystemExit(f"--exclude-selection takes SEED:COUNT, not {spec!r}")
        out.append((int(seed), int(count)))
    return out


def _select(args) -> int:
    listing = args.listing.read_text(encoding="utf-8").splitlines()
    parsed = samples.parse_listing(listing)
    exclude: frozenset[tuple[str, str]] = frozenset()
    for seed, count in _exclusions(args.exclude_selection):
        exclude |= samples.chosen_names(parsed, count, seed)
    chosen = samples.select(parsed, args.per_ecosystem, args.seed,
                            date.fromisoformat(args.cutoff), exclude)
    document = {"seed": args.seed, "cutoff": args.cutoff, "per_ecosystem": args.per_ecosystem,
                "excluded": {"selections": args.exclude_selection, "packages": len(exclude)},
                "samples": [s.to_dict() for s in chosen]}
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    if args.paths:
        args.paths.write_text("".join(s.path + "\n" for s in chosen), encoding="utf-8")
    counts = {e: sum(1 for s in chosen if s.ecosystem == e) for e in samples.ECOSYSTEMS}
    print(f"selected {len(chosen)} samples: {counts}, leaving out {len(exclude)} packages")
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
        exclude = frozenset(n for seed, count in _exclusions(args.exclude_selection)
                            for n in benign.sample_names(names, args.benign_top, count, seed,
                                                         ecosystem))
        for name in benign.sample_names(names, args.benign_top, args.benign_per_ecosystem,
                                        args.seed, ecosystem, exclude):
            row = {"set": "benign", "ecosystem": ecosystem, "name": name}
            try:
                row["version"], previous = benign.release_pair(ecosystem, name, as_of,
                                                               http_get)
                if args.version_pairs:
                    row["previous"] = previous
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
        findings: list | None = [] if args.triage else None
        row["bombsquad"] = tools.bombsquad(root, findings=findings)
        if findings:
            result = triage_eval.evaluate(findings, _triage_client(), sample is not None)
            if result is not None:
                row["triage"] = result
        row["guarddog"] = tools.guarddog(args.guarddog, row["ecosystem"], root)
        if sample is None and row.get("previous"):
            row["diff"] = tools.bombsquad_diff(row["ecosystem"], row["name"], row["previous"],
                                               row["version"])
        if args.detonate == "all" or (args.detonate == "benign" and sample is None):
            with _DETONATIONS:
                row["detonation"] = detonation.detonate(row, root, Path(work), sample is None,
                                                        http_get, args.detonate_timeout)
    return row


_DETONATIONS = threading.Semaphore(2)  # each runs two containers
_CLIENT: list = []
_CLIENT_LOCK = threading.Lock()


def _triage_client():
    with _CLIENT_LOCK:
        if not _CLIENT:
            import anthropic  # the triage extra

            _CLIENT.append(anthropic.Anthropic())
            # The client holds the key now; no tool or container started later inherits it.
            os.environ.pop("ANTHROPIC_API_KEY", None)
        return _CLIENT[0]


def _run(args) -> int:
    selection = json.loads(args.selected.read_text(encoding="utf-8"))
    chosen = [samples.Sample(**{**s, "splits": tuple(s["splits"])})
              for s in selection["samples"]]
    meta = {
        "started": datetime.now(UTC).isoformat(timespec="seconds"),
        "bombsquad": __version__, "bombsquad_commit": os.environ.get("GITHUB_SHA"),
        "guarddog": args.guarddog_version or tools.version(args.guarddog),
        "powershell": _powershell(),
        "dataset": "DataDog/malicious-software-packages-dataset",
        "dataset_commit": args.dataset_commit, "dataset_date": args.dataset_date,
        "seed": selection["seed"], "cutoff": selection["cutoff"],
        "malicious_per_ecosystem": selection["per_ecosystem"],
        "benign_lists": f"npm {benign.NPM_LIST_PACKAGE}@{benign.NPM_LIST_VERSION}, PyPI "
                        f"{benign.PYPI_LIST_REPO}@{benign.PYPI_LIST_COMMIT[:12]}",
        "benign_per_ecosystem": args.benign_per_ecosystem, "benign_top": args.benign_top,
        "benign_as_of": args.as_of,
        "detonate": args.detonate,
        "version_pairs": args.version_pairs,
    }
    if args.triage:
        if args.detonate == "all":
            raise SystemExit("benchmark: --triage needs an API key, which must not be on "
                             "the VM that runs malicious samples; leave out --detonate all")
        from bombsquad import triage

        meta["triage"] = {"model": triage.MODEL, "prompt_version": triage.PROMPT_VERSION,
                          "prompt_sha256": triage.prompt_digest(),
                          "notes_version": triage_eval.NOTES_VERSION}
        _triage_client()  # fails here, before any package, without the extra or a key
    if args.exclude_selection:
        meta["left_out"] = ("packages chosen with seed:count "
                            + ", ".join(args.exclude_selection))
    if args.detonate != "none":
        from bombsquad.detonate import runner
        meta["detonate_timeout"] = args.detonate_timeout
        for kind in ("npm", "pypi", "sink"):  # once, before the workers share them
            runner.build_image(kind)
    with tempfile.TemporaryDirectory(prefix="bench-lists-") as work:
        benign_rows = _benign_packages(args, Path(work)) if args.benign_per_ecosystem else []
    jobs: list[tuple[dict, samples.Sample | None]] = [
        ({"set": "malicious", "ecosystem": s.ecosystem, "name": s.name, "version": s.version,
          "kind": s.kind, "discovered": s.discovered, "splits": list(s.splits)}, s)
        for s in chosen]
    jobs += [(row, None) for row in benign_rows]
    if args.openssf:
        meta["openssf"] = {"repo": openssf.REPO, "commit": openssf.COMMIT,
                           "date": openssf.COMMIT_DATE}
        for row, sample in jobs:
            if sample is not None:
                row["openssf"] = openssf.lookup(args.openssf, row["ecosystem"], row["name"],
                                                row["version"])
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
    if meta.get("triage"):
        scores["triage"] = {**meta["triage"], **triage_eval.score(rows)}  # as the run had it
    if args.json:
        args.json.write_text(json.dumps(scores, indent=2) + "\n", encoding="utf-8")
    text = score.markdown(scores)
    if scores.get("triage"):
        text += "\n" + triage_eval.markdown(scores["triage"])
    if args.markdown:
        args.markdown.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def _openssf(args) -> int:
    selection = json.loads(args.selected.read_text(encoding="utf-8"))
    wanted = [(s["ecosystem"], s["name"]) for s in selection["samples"]]
    found = openssf.paths(args.listing.read_text(encoding="utf-8").splitlines(), wanted)
    args.paths.write_text("".join(f"{p}\n" for p in found), encoding="utf-8")
    names = {p.rsplit("/", 1)[0] for p in found}
    print(f"{len(found)} reports for {len(names)} of {len(wanted)} sampled names")
    return 0


def _incidents(args) -> int:
    found = incidents.find(incidents.INCIDENTS,
                           args.listing.read_text(encoding="utf-8").splitlines())
    if args.paths:
        args.paths.write_text("".join(f"{s.path}\n" for s in found.values()),
                              encoding="utf-8")
        print(f"{len(found)} of {len(incidents.INCIDENTS)} incident versions in the dataset")
        return 0
    if not (args.dataset and args.output):
        raise SystemExit("incidents: give --paths, or --dataset and --output")
    rows = []
    for incident in incidents.INCIDENTS:
        with tempfile.TemporaryDirectory(prefix="incident-", ignore_cleanup_errors=True) as work:
            try:
                rows.append(incidents.evaluate(incident, found.get(incident), args.dataset,
                                               Path(work), http_get))
            except Exception as exc:  # reported, as a benchmark row would be
                rows.append({**asdict(incident), "report_url": incident.report_url,
                             "status": f"error: {exc.__class__.__name__}: {str(exc)[:200]}"})
    args.output.write_text(json.dumps({"dataset_commit": args.dataset_commit, "incidents": rows},
                                      indent=2) + "\n", encoding="utf-8")
    text = incidents.markdown(rows, args.dataset_commit)
    if args.markdown:
        args.markdown.write_text(text, encoding="utf-8")
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
    s.add_argument("--exclude-selection", action="append", default=[], metavar="SEED:COUNT",
                   help="leave out the packages this seed and count would choose")

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
    r.add_argument("--exclude-selection", action="append", default=[], metavar="SEED:COUNT",
                   help="leave out the benign packages this seed and count would choose")
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--version-pairs", action="store_true",
                   help="also diff each benign release against the release before it, as "
                        "the pull-request gate reviews an update")
    r.add_argument("--detonate", choices=("none", "benign", "all"), default="none",
                   help="also detonate the benign packages, or every package, in the sandbox "
                        "(Linux with Docker)")
    r.add_argument("--detonate-timeout", type=int, default=detonation.TIMEOUT_SECONDS,
                   metavar="SECONDS")
    r.add_argument("--triage", action="store_true",
                   help="also run LLM triage on each package's flagged findings, and the "
                        "adversarial notes on malicious samples (Anthropic API, paid)")
    r.add_argument("--openssf", type=Path, metavar="CHECKOUT",
                   help=f"look up each malicious sample in {openssf.REPO} at commit "
                        f"{openssf.COMMIT[:12]}, checked out here")
    r.add_argument("--output", "-o", type=Path, required=True)

    o = sub.add_parser("openssf", help="list the OpenSSF report files for the sampled names")
    o.add_argument("--listing", type=Path, required=True,
                   help=f"the file listing of {openssf.REPO} at {openssf.COMMIT[:12]}")
    o.add_argument("--selected", type=Path, required=True)
    o.add_argument("--paths", type=Path, required=True)

    c = sub.add_parser("score", help="compute the scores from a results file")
    c.add_argument("results", type=Path)
    c.add_argument("--json", type=Path)
    c.add_argument("--markdown", type=Path)

    i = sub.add_parser("incidents", help="diff the named incident versions in the dataset")
    i.add_argument("--listing", type=Path, required=True)
    i.add_argument("--paths", type=Path, help="only write the samples' paths, one per line")
    i.add_argument("--dataset", type=Path, help="the dataset checkout")
    i.add_argument("--dataset-commit", default="")
    i.add_argument("--output", "-o", type=Path)
    i.add_argument("--markdown", type=Path)

    args = parser.parse_args(argv)
    return {"select": _select, "run": _run, "score": _score, "openssf": _openssf,
            "incidents": _incidents}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())

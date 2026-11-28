"""The static site and Atom feed, built from the flag log and the defusal record only.

Nothing the daily watch queued appears here until a person has reviewed it and listed it.
Every value that came from a registry or a package is escaped, links are built only from
names and versions that pass the registry's own rules or from https links a person
recorded, and the pages carry no script, with a content security policy that allows none.
"""

from __future__ import annotations

import html
import shutil
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from watch import ledger
from watch.review import LINK, ReviewError, listed, parse_release, report_states

TITLE = "Bomb Squad watch"
CSP = ("default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")
LIMITS = ("Listed means a person reviewed the update and chose to list what it newly gains. "
          "It is a change, not a verdict. Not listed does not mean safe: the diff is static, "
          "and cannot see code fetched or decoded at run time, or payloads gated on time or "
          "conditions. Publish times are the registry's, not when any change was made.")
ATOM = "http://www.w3.org/2005/Atom"

STYLE = """\
:root { --bg: #fbfbfa; --fg: #1d1d1b; --muted: #5d5d58; --line: #d9d8d2; --tag: #ecebe5;
  --high: #9c2a1a; --review: #7a5200; --link: #1f4f8f; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #161614; --fg: #e9e8e3; --muted: #a5a49d; --line: #393934; --tag: #26261f;
    --high: #f08a76; --review: #e0b660; --link: #8fb6ef; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 16px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
main, header, footer { max-width: 60rem; margin: 0 auto; padding: 0 16px; }
header { padding-top: 2rem; } footer { padding: 2rem 16px; color: var(--muted); font-size: .9rem; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; } h2 { font-size: 1.15rem; margin: 0; }
h2, code, .meta { overflow-wrap: anywhere; }
a { color: var(--link); } nav a { margin-right: 1rem; }
.limits { color: var(--muted); max-width: 46rem; }
article { border-top: 1px solid var(--line); padding: 1.25rem 0; }
.meta { color: var(--muted); font-size: .9rem; margin: .25rem 0 .75rem; }
code, pre { font: .85rem/1.45 ui-monospace, "Cascadia Mono", Consolas, monospace; }
pre { background: var(--tag); padding: .5rem .75rem; overflow-x: auto; white-space: pre-wrap;
  word-break: break-all; margin: .25rem 0; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; margin: .5rem 0; }
th, td { text-align: left; vertical-align: top; padding: .35rem .5rem;
  border-bottom: 1px solid var(--line); } th { color: var(--muted); font-weight: 600; }
.level { font-weight: 600; } .level-high { color: var(--high); }
.level-review { color: var(--review); }
.state { display: inline-block; background: var(--tag); padding: 0 .5rem; border-radius: 4px; }
.empty { color: var(--muted); padding: 2rem 0; }
.wrap { overflow-x: auto; }
"""


def esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def registry_url(release: str) -> str | None:
    """The release's page on its registry, from a name and version that pass its rules."""
    try:
        ecosystem, name, version = parse_release(release)
    except ReviewError:
        return None
    if ecosystem == "npm":
        return f"https://www.npmjs.com/package/{quote(name, safe='@/')}/v/{quote(version)}"
    return f"https://pypi.org/project/{quote(name)}/{quote(version)}/"


def link(url: str | None, text: str) -> str:
    if not url or not LINK.match(url):
        return esc(text)
    return f'<a href="{esc(url)}" rel="noreferrer noopener">{esc(text)}</a>'


def _page(title: str, body: str, heads: tuple[int, str], defusal_head: tuple[int, str]) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{esc(CSP)}">
<meta name="referrer" content="no-referrer">
<title>{esc(title)}</title>
<link rel="stylesheet" href="style.css">
<link rel="alternate" type="application/atom+xml" title="{esc(TITLE)}" href="feed.xml">
</head>
<body>
<header>
<h1>{esc(TITLE)}</h1>
<nav><a href="index.html">Listed updates</a><a href="defusals.html">Defusal record</a>
<a href="feed.xml">Feed</a></nav>
<p class="limits">{esc(LIMITS)}</p>
</header>
<main>
{body}
</main>
<footer>
<p>Built from <a href="flags.jsonl">the flag log</a>
({heads[0]} entries, head <code>{esc(heads[1][:16])}</code>) and
<a href="defusals.jsonl">the defusal record</a>
({defusal_head[0]} entries, head <code>{esc(defusal_head[1][:16])}</code>).
Both are append-only and hash-chained:
<code>python -m watch verify flags.jsonl --head SEQ:HASH</code>
checks that an entry you saw is unchanged.</p>
</footer>
</body>
</html>
"""


def _level(level: object) -> str:
    name = str(level) if level in ("high", "review") else "info"
    return f'<span class="level level-{name}">{esc(level)}</span>'


def _evidence(evidence: dict) -> str:
    parts = []
    if evidence.get("entry_points"):
        rows = "".join(
            f"<tr><td>{esc(e['surface'])}</td><td>{esc(e['kind'])}<br>"
            f"<small>runs on {esc(e['trigger'])}</small></td>"
            f"<td><code>{esc(e['path'])}:{esc(e['line'])}</code><pre>{esc(e['runs'])}</pre></td></tr>"
            for e in evidence["entry_points"])
        parts.append("<h3>New or changed entry points</h3><div class=\"wrap\"><table>"
                     "<tr><th>Surface</th><th>What</th><th>Where and what it runs</th></tr>"
                     f"{rows}</table></div>")
    if evidence.get("findings"):
        rows = "".join(
            f"<tr><td>{_level(f['level'])}</td><td><code>{esc(f['rule_id'])}</code> "
            f"{esc(f['title'])}<br><small>{esc(f['effect'])}</small></td>"
            f"<td><code>{esc(f['path'])}:{esc(f['line'])}</code><pre>{esc(f['evidence'])}</pre></td></tr>"
            for f in evidence["findings"])
        parts.append("<h3>New findings</h3><div class=\"wrap\"><table>"
                     "<tr><th>Level</th><th>Rule</th><th>Where and evidence</th></tr>"
                     f"{rows}</table></div>")
    if evidence.get("signals"):
        rows = "".join(f"<tr><td>{_level(s['level'])}</td><td><code>{esc(s['signal'])}</code></td>"
                       f"<td>{esc(s['detail'])}</td></tr>" for s in evidence["signals"])
        parts.append("<h3>Publish signals</h3><div class=\"wrap\"><table>"
                     "<tr><th>Level</th><th>Signal</th><th>Detail</th></tr>"
                     f"{rows}</table></div>")
    return "".join(parts)


def _report_text(report: dict) -> str:
    """A report and what became of it. Only a confirmed outcome, with its link, says the
    release is malicious."""
    states = []
    for outcome in report["outcomes"]:
        if outcome["outcome"] == "confirmed":
            text = link(outcome.get("link"), "confirmed malicious")
        else:
            text = link(outcome.get("link"), outcome["outcome"])
        states.append(f'<span class="state">{text}</span> {esc(outcome["recorded"][:10])}')
    current = " ".join(states) or '<span class="state">open</span>'
    return (f"Reported to {esc(report['reported_to'])} on {esc(report['recorded'][:10])} "
            f"({link(report['reference'], 'report')}): {current}")


def _flag(entry: dict, reports: list[dict]) -> str:
    release = entry["release"]
    compared = entry.get("compared_with")
    try:
        ecosystem, name, _ = parse_release(release)
        command = f"bombsquad diff {ecosystem}:{name}@{compared}..{release.rpartition('@')[2]}"
    except ReviewError:
        command = ""
    mine = [r for r in reports if r["flag"] == entry["seq"]]
    reported = "".join(f"<p>{_report_text(r)}</p>" for r in mine)
    reasons = "".join(f"<li>{esc(r)}</li>" for r in entry.get("reasons") or [])
    return f"""<article id="flag-{entry['seq']}">
<h2>{link(registry_url(release), release)}</h2>
<p class="meta">Compared with {esc(compared)} · published {esc(entry.get('published'))}
· reviewed {esc(entry['recorded'])} by {esc(entry.get('reviewer'))}
· <a href="#flag-{entry['seq']}">flag {entry['seq']}</a></p>
<ul>{reasons}</ul>
<p><strong>Review:</strong> {esc(entry.get('note'))}</p>
{_evidence(entry.get('evidence') or {})}
{reported}
<p class="meta">Reproduce: <code>{esc(command)}</code></p>
</article>"""


def _defusal_page(reports: list[dict]) -> str:
    if not reports:
        return '<p class="empty">No report has been made yet.</p>'
    rows = "".join(
        f"<tr><td>{esc(r['recorded'][:10])}</td>"
        f"<td>{link(registry_url(r['release']), r['release'])}</td>"
        f"<td><a href=\"index.html#flag-{r['flag']}\">flag {r['flag']}</a></td>"
        f"<td>{_report_text(r)}</td></tr>" for r in reversed(reports))
    return ("<h2>Defusal record</h2><p class=\"limits\">Each report sent to a registry or to "
            "OpenSSF malicious-packages about a listed update, and what became of it. "
            "Entries are only ever added.</p><div class=\"wrap\"><table><tr><th>Reported</th>"
            f"<th>Release</th><th>Flag</th><th>State</th></tr>{rows}</table></div>")


def feed(entries: list[dict], base_url: str, updated: str) -> bytes:
    ET.register_namespace("", ATOM)
    root = ET.Element(f"{{{ATOM}}}feed")
    ET.SubElement(root, f"{{{ATOM}}}title").text = TITLE
    ET.SubElement(root, f"{{{ATOM}}}id").text = base_url + "feed.xml"
    ET.SubElement(root, f"{{{ATOM}}}updated").text = updated
    ET.SubElement(root, f"{{{ATOM}}}link", href=base_url, rel="alternate")
    ET.SubElement(root, f"{{{ATOM}}}link", href=base_url + "feed.xml", rel="self")
    author = ET.SubElement(root, f"{{{ATOM}}}author")
    ET.SubElement(author, f"{{{ATOM}}}name").text = TITLE
    for entry in entries:
        item = ET.SubElement(root, f"{{{ATOM}}}entry")
        url = f"{base_url}index.html#flag-{entry['seq']}"
        ET.SubElement(item, f"{{{ATOM}}}title").text = (
            f"{entry['release']} (compared with {entry.get('compared_with')})")
        ET.SubElement(item, f"{{{ATOM}}}id").text = url
        ET.SubElement(item, f"{{{ATOM}}}updated").text = entry["recorded"]
        ET.SubElement(item, f"{{{ATOM}}}link", href=url, rel="alternate")
        summary = ET.SubElement(item, f"{{{ATOM}}}summary", type="text")
        summary.text = "; ".join([*(entry.get("reasons") or []), f"Review: {entry.get('note')}",
                                  LIMITS])
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def build(flags_path: Path, defusals_path: Path, out: Path, base_url: str,
          now: datetime) -> dict:
    """Write the site into `out`, after checking both chains. Returns what was built."""
    if not (LINK.match(base_url) and base_url.endswith("/")):
        raise ValueError("the base URL is an https URL ending in /")
    flags = ledger.verify(flags_path)
    defusals = ledger.verify(defusals_path)
    shown = sorted(listed(flags).values(), key=lambda e: e["seq"], reverse=True)
    reports = report_states(defusals)
    heads, defusal_head = ledger.head(flags), ledger.head(defusals)
    body = "".join(_flag(e, reports) for e in shown) or (
        '<p class="empty">No update has been listed yet.</p>')
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(_page(TITLE, body, heads, defusal_head), encoding="utf-8")
    (out / "defusals.html").write_text(
        _page(f"Defusal record · {TITLE}", _defusal_page(reports), heads, defusal_head),
        encoding="utf-8")
    (out / "style.css").write_text(STYLE, encoding="utf-8")
    times = [e["recorded"] for e in [*flags, *defusals]]
    updated = max(times) if times else now.isoformat(timespec="seconds")
    (out / "feed.xml").write_bytes(feed(shown, base_url, updated))
    for source, name in ((flags_path, "flags.jsonl"), (defusals_path, "defusals.jsonl")):
        if source.exists():
            shutil.copyfile(source, out / name)
        else:
            (out / name).write_text("", encoding="utf-8")
    return {"listed": len(shown), "reports": len(reports), "flags_head": heads,
            "defusals_head": defusal_head}


__all__ = ["build", "esc", "feed", "registry_url"]

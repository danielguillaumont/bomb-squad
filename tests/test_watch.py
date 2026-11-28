"""The daily watch: which releases are new in a window, what each is compared with, and why
one is queued for review. No test touches the network: a fake registry serves metadata and
the diff is stubbed."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from tests.test_diff import Registry
from watch import daily

SINCE = datetime(2026, 11, 26, tzinfo=UTC)
UNTIL = datetime(2026, 11, 27, tzinfo=UTC)


def test_new_releases_in_the_window_are_paired_with_the_one_before():
    registry = Registry()
    registry.urls["https://registry.npmjs.org/demo"] = json.dumps({
        "versions": {v: {} for v in ("1.0.0", "1.1.0", "1.1.1", "2.0.0-rc.1", "0.9.9",
                                     "1.2.0")},
        "time": {"1.0.0": "2026-01-01T00:00:00Z", "1.1.0": "2026-06-01T00:00:00Z",
                 "1.1.1": "2026-11-26T08:00:00Z",
                 "2.0.0-rc.1": "2026-11-26T09:00:00Z",  # a pre-release: left out
                 "0.9.9": "2026-11-26T10:00:00Z",  # a backport: compared with what is below
                 "1.2.0": "2026-11-27T00:00:00Z"}}).encode()  # at the end: next window
    found = daily.new_releases("npm", "demo", SINCE, UNTIL, registry)
    assert [(r["version"], r["previous"]) for r in found] == [("1.1.1", "1.1.0"),
                                                              ("0.9.9", None)]
    assert found[0]["published"] == "2026-11-26T08:00:00+00:00"


def test_a_release_is_queued_only_for_what_it_newly_gains():
    def stub(result):
        return lambda *args: {"error": None, "entry_points": {"added": 0, "changed": 0},
                              "signals": ["recent-release:review"], **result}

    base = {"ecosystem": "npm", "name": "demo", "version": "1.1.1", "previous": "1.1.0",
            "published": "2026-11-26T08:00:00+00:00"}
    quiet = daily.check(base, stub({}))
    assert quiet["status"] == "nothing new found" and quiet["reasons"] == []
    hook = daily.check(base, stub({"entry_points": {"added": 2, "changed": 0,
                                                    "surfaces": ["github-actions", "npm"],
                                                    "run_on_install": 1,
                                                    "install_surfaces": ["npm"]},
                                   "rules_by_level": {"high": ["BS-EX-001"]},
                                   "signals": ["publisher-changed:review",
                                               "recent-release:review"]}))
    assert hook["status"] == "queued for review"
    assert hook["reasons"] == ["1 new or changed entry points that installing runs (npm)",
                               "new high findings: BS-EX-001", "publish signal: publisher-changed"]
    failed = daily.check(base, stub({"error": "exit 2: boom"}))
    assert failed["status"] == "error"
    first = daily.check({**base, "previous": None}, stub({}))
    assert first["status"] == "no earlier release to compare with" and "diff" not in first
    text = daily.markdown({"since": "a", "until": "b", "packages": 1}, [quiet, hook, failed])
    assert "1 queued for review, 1 that could not be compared" in text
    assert "npm:demo@1.1.1" in text and "Not queued does not mean safe." in text

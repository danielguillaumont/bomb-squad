"""LLM triage, with a fake client: nothing here calls the API."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from benchmark import triage_eval
from bombsquad import cli, triage


def finding(rule: str, level: str, line: int, evidence: str = "x", path: str = "a.js") -> dict:
    return {"rule_id": rule, "title": f"title {rule}", "level": level, "path": path,
            "line": line, "evidence": evidence}


FINDINGS = [
    finding("R1", "info", 1),
    finding("R2", "review", 2),
    finding("R3", "high", 3),
    finding("R4", "review", 4),
    finding("R5", "low", 5),
    finding("R6", "high", 6),
]


class Fake:
    """Answers with the given assessments, keyed by hunk id, and keeps every request."""

    def __init__(self, answer=None, *, stop_reason="end_turn", text=None, model=None):
        self.requests: list[dict] = []
        self.answer = answer or (lambda hunks: [])
        self.stop_reason, self.text, self.model = stop_reason, text, model
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(kwargs)
        content = kwargs["messages"][0]["content"]
        sent = json.loads(content.split("<findings>\n", 1)[1].rsplit("\n</findings>", 1)[0])
        text = self.text if self.text is not None else json.dumps(
            {"findings": self.answer(sent)})
        return SimpleNamespace(stop_reason=self.stop_reason, model=self.model or triage.MODEL,
                               content=[SimpleNamespace(type="text", text=text)])


def by_rule(mapping: dict[str, str], addressed: tuple[str, ...] = ()):
    def answer(sent):
        return [{"id": h["id"], "concern": mapping[h["rule"]],
                 "addressed_to_reviewer": h["rule"] in addressed,
                 "explanation": f"because {h['rule']}"} for h in sent if h["rule"] in mapping]
    return answer


def rules(result: triage.Triage, findings=FINDINGS) -> list[str]:
    return [findings[i]["rule_id"] for i in result.order]


def test_only_flagged_findings_are_sent_high_first():
    sent = [h for _, h in triage.hunks(FINDINGS)]
    assert [h["rule"] for h in sent] == ["R3", "R6", "R2", "R4"]
    assert [h["id"] for h in sent] == [1, 2, 3, 4]
    assert set(sent[0]) == {"id", "rule", "level", "title", "where", "excerpt"}


def test_excerpts_are_cut_and_hunks_capped():
    many = [finding(f"R{i}", "review", i, "y" * 5000) for i in range(triage.MAX_HUNKS + 5)]
    sent = triage.hunks(many)
    assert len(sent) == triage.MAX_HUNKS
    assert all(len(h["excerpt"]) <= triage.EXCERPT_CHARS + len(" [cut]") for _, h in sent)


def test_the_request_uses_structured_output_fallbacks_and_marks_excerpts_untrusted():
    fake = Fake(by_rule({}))
    triage.triage(FINDINGS, fake)
    (request,) = fake.requests
    assert request["model"] == triage.MODEL
    assert request["betas"] == [triage.FALLBACK_BETA]
    assert request["fallbacks"] == "default"
    assert request["output_config"]["format"] == {"type": "json_schema",
                                                  "schema": triage.SCHEMA}
    assert "untrusted" in request["system"] and "untrusted" in request["messages"][0]["content"]
    assert "thinking" not in request and "budget_tokens" not in json.dumps(request)


def test_the_order_is_every_finding_once_and_nothing_is_dropped():
    fake = Fake(by_rule({"R3": "low", "R6": "low", "R2": "low", "R4": "low"}))
    result = triage.triage(FINDINGS, fake)
    assert sorted(result.order) == list(range(len(FINDINGS)))
    # all called low: still the flagged ones first, unflagged after in report order
    assert rules(result) == ["R3", "R6", "R2", "R4", "R1", "R5"]


def test_concern_reorders_flagged_findings():
    fake = Fake(by_rule({"R3": "low", "R6": "medium", "R2": "high"}))
    result = triage.triage(FINDINGS, fake)
    # high concern, then the unassessed R4, then medium, then low
    assert rules(result) == ["R2", "R4", "R6", "R3", "R1", "R5"]
    assert result.assessments[1].explanation == "because R2"


def test_text_addressed_to_a_reviewer_raises_the_concern():
    fake = Fake(by_rule({"R3": "low", "R2": "low"}, addressed=("R2",)))
    result = triage.triage(FINDINGS, fake)
    assert result.assessments[1].concern == "high"
    assert result.assessments[1].addressed_to_reviewer
    assert rules(result)[0] == "R2"


def test_unknown_repeated_and_malformed_answers_are_ignored():
    def answer(sent):
        return [{"id": 99, "concern": "low", "addressed_to_reviewer": False, "explanation": ""},
                {"id": 1, "concern": "medium", "addressed_to_reviewer": False,
                 "explanation": ""},
                {"id": 1, "concern": "low", "addressed_to_reviewer": False, "explanation": ""},
                {"id": 2, "concern": "none", "addressed_to_reviewer": False,
                 "explanation": ""},
                "junk"]
    result = triage.triage(FINDINGS, Fake(answer))
    assert {i: a.concern for i, a in result.assessments.items()} == {2: "medium"}
    assert sorted(result.order) == list(range(len(FINDINGS)))


@pytest.mark.parametrize("fake", [Fake(stop_reason="refusal"), Fake(text="not json")])
def test_a_refusal_or_unusable_answer_leaves_the_report_order(fake):
    with pytest.raises(triage.TriageUnavailable):
        triage.triage(FINDINGS, fake)


def test_nothing_flagged_sends_nothing():
    fake = Fake()
    result = triage.triage([finding("R1", "info", 1)], fake)
    assert fake.requests == [] and result.sent == 0 and result.order == [0]


def test_a_fallback_model_is_named():
    result = triage.triage(FINDINGS, Fake(by_rule({}), model="claude-fallback"))
    assert result.served_by == "claude-fallback"
    assert "claude-fallback" in triage.render(result, FINDINGS)


def test_a_diff_report_triages_the_added_findings():
    report = {"kind": "diff", "findings": {"added": FINDINGS[:2], "removed": FINDINGS[2:]}}
    assert triage.report_findings(report) == FINDINGS[:2]
    with pytest.raises(ValueError):
        triage.report_findings({"kind": "gate"})


def test_the_json_result_keeps_every_finding_and_names_the_prompt():
    result = triage.triage(FINDINGS, Fake(by_rule({"R2": "high"})))
    data = result.to_dict(FINDINGS)
    assert len(data["order"]) == len(FINDINGS)
    assert data["prompt_sha256"] == triage.prompt_digest()
    assert data["order"][0]["triage"]["concern"] == "high"
    assert any("not a verdict" in text for text in data["limitations"])


def args(tmp_path, report, fmt="json"):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return SimpleNamespace(report=path, format=fmt, output=tmp_path / "out")


def test_cli_triages_a_report_with_an_injected_client(tmp_path, capsys):
    a = args(tmp_path, {"findings": FINDINGS})
    assert cli._triage(a, Fake(by_rule({"R2": "high"}))) == cli.EXIT_OK
    out = json.loads(a.output.read_text(encoding="utf-8"))
    assert out["order"][0]["rule_id"] == "R2"
    assert "sending 4 flagged excerpts" in capsys.readouterr().err


def test_cli_text_output_and_refusal(tmp_path, capsys):
    a = args(tmp_path, {"findings": FINDINGS}, fmt="text")
    assert cli._triage(a, Fake(by_rule({}))) == cli.EXIT_OK
    assert "(not assessed)" in a.output.read_text(encoding="utf-8")
    assert cli._triage(a, Fake(stop_reason="refusal")) == cli.EXIT_ERROR
    assert "order stands" in capsys.readouterr().err


def test_cli_rejects_a_report_it_cannot_read(tmp_path):
    assert cli._triage(args(tmp_path, {"kind": "gate"}), Fake()) == cli.EXIT_ERROR
    missing = SimpleNamespace(report=tmp_path / "nope.json", format="json", output=None)
    assert cli._triage(missing, Fake()) == cli.EXIT_ERROR


def test_eval_counts_a_finding_talked_down_by_a_note():
    def answer(sent):
        return [{"id": h["id"], "concern": "low" if "reviewer" in h["excerpt"] else "high",
                 "addressed_to_reviewer": False, "explanation": ""} for h in sent]

    result = triage_eval.adversarial(FINDINGS, Fake(answer))
    assert result["findings"] == 4 and result["assessed_pairs"] == 4 * len(triage_eval.NOTES)
    # the notes that mention a reviewer talk it down; the order still never drops one
    reviewer = sum("reviewer" in note for note in triage_eval.NOTES)
    assert result["talked_down"] == 4 * reviewer


def test_eval_injects_a_comment_in_the_file_language():
    assert triage_eval.inject(finding("R", "high", 1, "code", "a.py"), "hi")["evidence"] \
        == "# hi\ncode"
    assert triage_eval.inject(finding("R", "high", 1, "code", "a.js"), "hi")["evidence"] \
        .startswith("// hi")


def test_a_benchmark_row_keeps_concerns_not_explanations():
    row = triage_eval.evaluate(FINDINGS, Fake(by_rule({"R2": "high", "R3": "low"})), True)
    assert row["concern"] == "high" and row["sent"] == 4 and row["assessed"] == 2
    assert set(row["adversarial"]) == {"assessed_pairs", "talked_down", "noticed"}
    assert "because" not in json.dumps(row)
    assert "adversarial" not in triage_eval.evaluate(FINDINGS, Fake(by_rule({})), False)
    assert triage_eval.evaluate([finding("R1", "info", 1)], Fake(), True) is None
    assert "error" in triage_eval.evaluate(FINDINGS, Fake(stop_reason="refusal"), False)


def test_the_benchmark_scores_triage_with_the_run_meta():
    rows = [{"set": "malicious", "ecosystem": "npm", "bombsquad": {"levels": ["review"]},
             "triage": {"concern": "high", "adversarial": {"assessed_pairs": 6,
                                                           "talked_down": 1, "noticed": 5}}},
            {"set": "benign", "ecosystem": "npm", "bombsquad": {"levels": ["review"]},
             "triage": {"error": "declined"}},
            {"set": "benign", "ecosystem": "npm", "prepare_error": "x"}]
    scores = triage_eval.score(rows)
    assert scores["adversarial"] == {"assessed_pairs": 6, "talked_down": 1, "noticed": 5}
    assert scores["errors"] == 1
    text = triage_eval.markdown({"model": "m", "prompt_version": "1", "notes_version": "1",
                                 **scores})
    assert "1 of 6" in text and "| npm | Triage, high concern | 1/1 (100.0%) |" in text


def test_the_benchmark_refuses_triage_on_the_detonation_vm(tmp_path):
    from benchmark import __main__ as bench

    selected = tmp_path / "selected.json"
    selected.write_text(json.dumps({"samples": [], "seed": 1, "cutoff": "2026-01-01",
                                    "per_ecosystem": 0}), encoding="utf-8")
    with pytest.raises(SystemExit, match="detonate all"):
        bench.main(["run", "--selected", str(selected), "--dataset", str(tmp_path),
                    "--dataset-commit", "c", "--dataset-date", "2026-01-01",
                    "--as-of", "2026-01-01", "--guarddog-version", "3",
                    "--detonate", "all", "--triage", "-o", str(tmp_path / "out.jsonl")])


def test_eval_operating_points_per_ecosystem():
    rows = [
        {"set": "malicious", "ecosystem": "npm", "levels": ["high"], "triage": "high"},
        {"set": "malicious", "ecosystem": "npm", "levels": ["review"], "triage": "low"},
        {"set": "benign", "ecosystem": "npm", "levels": ["review"], "triage": "low"},
        {"set": "benign", "ecosystem": "npm", "levels": [], "triage": None},
    ]
    points = {p["detector"]: p for p in triage_eval.operating_points(rows)}
    assert points["Bomb Squad, a review or high finding"]["recall"] == (2, 2)
    assert points["Bomb Squad, a review or high finding"]["false_positives"] == (1, 2)
    assert points["Triage, high concern"]["recall"] == (1, 2)
    assert points["Triage, high concern"]["false_positives"] == (0, 2)

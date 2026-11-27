"""`using module` and `using assembly` make the PowerShell parser open the named file, so
Bomb Squad blanks them before parsing and reports them instead."""

from __future__ import annotations

from bombsquad.powershell.parser import blank_using_statements, utf16_len
from tests.conftest import analyse


def test_parser_never_reads_the_module(tmp_path):
    # If the parser read evil.psm1 it would know class Foo and report no error.
    module = tmp_path / "evil.psm1"
    module.write_text("class Foo { }\n", encoding="utf-8")
    source = f"using module {module}\nclass Bar : Foo {{ }}\n"
    _, findings, results = analyse({"script": source})
    assert any("Foo" in e["message"] for e in results["script"].parse_errors)
    assert {f.rule.id for f in findings["script"]} == {"BS-DE-005"}


def test_blanking_keeps_offsets_lines_and_columns():
    source = ("#requires -Version 5\r\n"
              "<# note #> using module '\\\\host\\share\\m.psm1'\r\n"
              "Get-Date\r\n")
    blanked, found = blank_using_statements(source)
    assert utf16_len(blanked) == utf16_len(source)
    assert blanked.splitlines()[2] == "Get-Date"
    assert "using" not in blanked
    assert [(u.kind, u.span.line, u.span.column) for u in found] == [("module", 2, 12)]


def test_blanking_handles_continuations_and_several_statements():
    source = "using namespace System.IO\nusing `\n  assembly C:\\x.dll; using module M\nls\n"
    blanked, found = blank_using_statements(source)
    assert [u.kind for u in found] == ["assembly", "module"]
    assert "using namespace System.IO" in blanked
    assert "assembly" not in blanked and "module" not in blanked


def test_blanking_keeps_utf16_length_with_astral_characters():
    source = "using module 'C:\\\U0001F4A3.psm1'\nGet-Date\n"
    blanked, _ = blank_using_statements(source)
    assert utf16_len(blanked) == utf16_len(source)


def test_using_after_code_is_left_alone():
    source = "Get-Date\nusing module M\n"
    blanked, found = blank_using_statements(source)
    assert blanked == source and found == []

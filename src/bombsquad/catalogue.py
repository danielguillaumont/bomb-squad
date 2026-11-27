"""Every rule Bomb Squad can report."""

from bombsquad.code.rules import RULES as CODE_RULES
from bombsquad.model import Rule
from bombsquad.powershell.rules import RULES as POWERSHELL_RULES

ALL_RULES: dict[str, Rule] = {**POWERSHELL_RULES, **CODE_RULES}

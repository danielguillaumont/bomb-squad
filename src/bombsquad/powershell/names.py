"""Resolve the many names PowerShell accepts for the same operation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

CMDLETS = {
    name.lower(): name
    for name in (
        "Add-LocalGroupMember", "Add-MpPreference", "Add-Type", "Get-ChildItem", "Get-Item",
        "Import-Module",
        "Invoke-Command", "Invoke-Expression", "Invoke-RestMethod", "Invoke-WebRequest",
        "New-Item", "New-ItemProperty", "New-LocalUser", "New-Object", "New-Service",
        "Register-ScheduledTask", "Remove-Item", "Remove-ItemProperty", "Set-ItemProperty",
        "Set-MpPreference", "Set-ScheduledTask", "Set-Service", "Start-BitsTransfer",
        "Start-Process",
    )
}

# Built-in aliases in both Windows PowerShell 5.1 and PowerShell 7.
ALIASES = {
    "del": "Remove-Item", "erase": "Remove-Item", "rd": "Remove-Item", "ri": "Remove-Item",
    "rm": "Remove-Item", "rmdir": "Remove-Item",
    "iex": "Invoke-Expression", "iwr": "Invoke-WebRequest", "irm": "Invoke-RestMethod",
    "icm": "Invoke-Command", "ipmo": "Import-Module", "ni": "New-Item",
    "rp": "Remove-ItemProperty", "sp": "Set-ItemProperty", "saps": "Start-Process",
    "start": "Start-Process", "gci": "Get-ChildItem", "dir": "Get-ChildItem",
    "gi": "Get-Item",
}

NATIVE_TOOLS = frozenset({
    "bitsadmin", "certutil", "curl", "net", "net1", "powershell", "pwsh", "reg", "sc",
    "schtasks", "wget",
})

# Names whose meaning depends on the PowerShell version or platform.
VERSION_NOTES = {
    "curl": "In Windows PowerShell 5.1, curl is an alias for Invoke-WebRequest; "
            "elsewhere it is curl.exe. Both download.",
    "wget": "In Windows PowerShell 5.1, wget is an alias for Invoke-WebRequest; "
            "elsewhere it is the wget program. Both download.",
    "sc": "In Windows PowerShell 5.1, sc is an alias for Set-Content; in PowerShell 7 it is "
          "sc.exe, the service control tool.",
}

_MODULE_QUALIFIED = re.compile(r"^[A-Za-z][\w.]*\\([A-Za-z]+-[A-Za-z][\w]*)$")
_EXECUTABLE_SUFFIXES = (".exe", ".com")


@dataclass(frozen=True)
class Resolved:
    kind: str  # cmdlet | native | other
    name: str  # canonical cmdlet name, lower-case tool name, or the name as written
    via: tuple[str, ...] = field(default=())


def resolve(raw: str) -> Resolved:
    name = raw.strip()
    via: list[str] = []
    qualified = _MODULE_QUALIFIED.match(name)
    if qualified:
        via.append(f"module-qualified name {name}")
        name = qualified.group(1)
    elif "\\" in name or "/" in name:
        base = re.split(r"[\\/]", name)[-1]
        via.append(f"path {name}")
        name = base
    lower = name.lower()
    for suffix in _EXECUTABLE_SUFFIXES:
        if lower.endswith(suffix):
            tool = lower[: -len(suffix)]
            if tool in NATIVE_TOOLS:
                return Resolved("native", tool, tuple(via))
            return Resolved("other", name, tuple(via))
    if lower in VERSION_NOTES:
        return Resolved("native", lower, (*via, VERSION_NOTES[lower]))
    if lower in ALIASES:
        return Resolved("cmdlet", ALIASES[lower], (*via, f"alias {name} for {ALIASES[lower]}"))
    if lower in CMDLETS:
        return Resolved("cmdlet", CMDLETS[lower], tuple(via))
    if lower in NATIVE_TOOLS:
        return Resolved("native", lower, tuple(via))
    return Resolved("other", name, tuple(via))


def strip_switch(name: str) -> str:
    """Lower-case a native-tool switch without its leading -, /, or dash-like characters."""
    return name.lower().lstrip("-/–—―")


def is_encoded_command_switch(name: str) -> bool:
    """powershell.exe and pwsh accept -e, -ec and any prefix of -EncodedCommand."""
    switch = strip_switch(name)
    return switch in ("e", "ec") or (len(switch) >= 2 and "encodedcommand".startswith(switch))


def is_command_switch(name: str) -> bool:
    """powershell.exe and pwsh accept -c and prefixes of -Command from three letters."""
    switch = strip_switch(name)
    return switch == "c" or (len(switch) >= 3 and "command".startswith(switch))


REGISTRY_ROOTS = re.compile(
    r"^(?:(?:microsoft\.powershell\.core\\)?registry::)?"
    r"(hklm|hkcu|hkcr|hku|hkcc|hkey_local_machine|hkey_current_user|hkey_classes_root|"
    r"hkey_users|hkey_current_config)(?::|\\|$)",
    re.IGNORECASE,
)

AUTOSTART_KEYS = (
    r"\currentversion\run", r"\currentversion\policies\explorer\run",
    r"\currentversion\winlogon", r"\image file execution options", r"\currentcontrolset\services",
)


def registry_class(path: str | None) -> str | None:
    """Classify a registry path: None when it is not a registry path at all."""
    if path is None or not REGISTRY_ROOTS.match(path.strip().strip("'\"")):
        return None
    lower = path.lower().replace("/", "\\")
    if "\\windows defender" in lower:
        return "defender-exclusion" if "\\exclusions" in lower else "defender"
    if "\\powershell\\scriptblocklogging" in lower or "\\powershell\\modulelogging" in lower:
        return "logging"
    if any(key in lower for key in AUTOSTART_KEYS):
        return "autostart"
    return "registry"

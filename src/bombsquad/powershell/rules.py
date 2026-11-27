"""The PowerShell rule catalogue. v1 rule IDs keep their meaning."""

from bombsquad.model import Level, Rule

_RUNTIME_PATH = "The target is not resolved when it comes from a variable or another command."

RULES: dict[str, Rule] = {r.id: r for r in (
    Rule(
        "BS-FS-001", "filesystem", "Deletes files or directories", Level.REVIEW,
        "If run, this deletes the items at the target path.",
        "Check what the path points to and whether -Recurse or -Force widen it.",
        (_RUNTIME_PATH,),
    ),
    Rule(
        "BS-SS-001", "security-settings", "Changes Microsoft Defender settings", Level.HIGH,
        "If run, this changes how Microsoft Defender protects the machine.",
        "Confirm why a script needs to change Defender settings at all.",
    ),
    Rule(
        "BS-SS-002", "security-settings", "Adds a Microsoft Defender exclusion", Level.HIGH,
        "If run, Defender stops scanning the excluded paths, extensions, processes or "
        "addresses. Malware commonly does this before dropping files.",
        "Do not run this unless you know exactly why the exclusion is needed.",
    ),
    Rule(
        "BS-RG-001", "registry", "Writes to the registry", Level.REVIEW,
        "If run, this creates, changes or deletes registry keys or values.",
        "Check the key and value against what the script says it does.",
        (_RUNTIME_PATH,),
    ),
    Rule(
        "BS-RG-002", "persistence", "Writes to a registry autostart location", Level.HIGH,
        "If run, this changes a key Windows reads at logon or service start, so a program "
        "can run again without anyone starting it.",
        "Identify the program the key would start and whether it should start "
        "automatically.",
    ),
    Rule(
        "BS-ID-001", "identity", "Changes local accounts or groups", Level.REVIEW,
        "If run, this creates or changes a local user or group membership.",
        "Check which account is created or which group it joins; Administrators is the "
        "one that matters most.",
    ),
    Rule(
        "BS-TS-001", "persistence", "Creates or changes a scheduled task or service",
        Level.REVIEW,
        "If run, this registers something Windows will run later, at a trigger or as a "
        "service.",
        "Identify what the task or service runs and when.",
    ),
    Rule(
        "BS-DE-001", "dynamic-execution", "Evaluates text as PowerShell", Level.REVIEW,
        "If run, text is executed as PowerShell code. What runs depends on that text.",
        "Find where the text comes from. If it is downloaded or decoded, review that "
        "content too.",
        ("Text that is built or fetched at run time is not analysed.",),
    ),
    Rule(
        "BS-DE-002", "dynamic-execution", "Builds a script block from text", Level.REVIEW,
        "If run, text is turned into executable PowerShell code.",
        "Find where the text comes from and review it as code.",
        ("Text that is built or fetched at run time is not analysed.",),
    ),
    Rule(
        "BS-DE-003", "dynamic-execution", "Calls a command chosen at run time", Level.REVIEW,
        "If run, the command that executes is decided by a variable or expression, so "
        "reading the script does not show what runs.",
        "Trace the variable or expression to the command it names.",
    ),
    Rule(
        "BS-DE-004", "dynamic-execution", "Compiles or loads .NET code", Level.REVIEW,
        "If run, C# source is compiled or an assembly is loaded into PowerShell. That code "
        "can call any Windows API, including ones used to disable security tools.",
        "Review the compiled source or the assembly's origin.",
    ),
    Rule(
        "BS-DE-005", "dynamic-execution", "Loads a module or assembly", Level.REVIEW,
        "If run, code from another file or location is loaded. Bomb Squad does not open "
        "that file, so its contents are not analysed.",
        "Review the module or assembly the script loads.",
    ),
    Rule(
        "BS-EN-001", "obfuscation", "Runs an encoded PowerShell command", Level.HIGH,
        "If run, PowerShell executes base64-encoded code that cannot be read in the "
        "script. Bomb Squad decodes it and analyses the result.",
        "Read the decoded command shown in the finding before running anything.",
    ),
    Rule(
        "BS-EN-002", "obfuscation", "Decodes embedded base64 text", Level.INFO,
        "The script carries base64 text that it decodes at run time. Bomb Squad decodes "
        "it too and analyses it when it is PowerShell.",
        "Check what the decoded text is used for.",
    ),
    Rule(
        "BS-NET-001", "network", "Downloads content", Level.REVIEW,
        "If run, this fetches content from a network location.",
        "Check the URL and what is done with the downloaded content.",
        ("The URL may be built at run time and the content is not fetched.",),
    ),
    Rule(
        "BS-NET-002", "network", "Downloads and runs code", Level.HIGH,
        "If run, content fetched from the network is executed. Whoever controls that URL "
        "controls what runs, and the code can change after this review.",
        "Do not run this. Fetch the content separately and review it as its own script.",
        ("The downloaded content is not fetched or analysed.",),
    ),
    Rule(
        "BS-AV-001", "security-settings", "Tampers with AMSI or PowerShell logging",
        Level.HIGH,
        "The script refers to internals used to switch off the Antimalware Scan Interface "
        "or PowerShell script logging, which hides later activity from security tools.",
        "Treat the script as hostile unless its purpose is security testing you control.",
    ),
)}

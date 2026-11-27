"""Rules for code that runs on its own: install hooks, startup files, test bootstraps."""

from bombsquad.model import Level, Rule

RULES: dict[str, Rule] = {r.id: r for r in (
    Rule(
        "BS-EP-001", "auto-execution", "Runs code at every Python start", Level.REVIEW,
        "Python executes this code each time any Python process starts on the machine, "
        "without an import. Malicious packages use .pth files for exactly this.",
        "Check why the package needs code to run at interpreter start; very few do.",
    ),
    Rule(
        "BS-NET-003", "network", "Opens network connections", Level.REVIEW,
        "Code that runs on its own can reach the network, so it can fetch more code or "
        "send data out.",
        "Check which hosts it contacts and what it sends.",
        ("Destinations built at run time are not resolved.",),
    ),
    Rule(
        "BS-PRC-001", "process", "Starts other programs", Level.INFO,
        "Code that runs on its own starts other programs. Build steps do this often; "
        "the program it starts decides the risk.",
        "Check which program is started and with which arguments.",
    ),
    Rule(
        "BS-CR-001", "credentials", "Reads credential files or tokens", Level.REVIEW,
        "The code names a credential file or token variable, such as ~/.npmrc, "
        "~/.aws/credentials, ~/.ssh or GITHUB_TOKEN. Credential stealers look in "
        "exactly these places.",
        "Confirm the code has a legitimate reason to touch that credential.",
    ),
    Rule(
        "BS-ENV-001", "credentials", "Collects all environment variables", Level.REVIEW,
        "The code reads or serialises the whole environment, which on a developer machine "
        "or CI runner holds tokens and keys.",
        "Check where the collected values go.",
        ("Passing the environment to a child process is not reported.",),
    ),
    Rule(
        "BS-DE-006", "dynamic-execution", "Evaluates text as code", Level.REVIEW,
        "Text is executed as code at run time, so reading the file does not show what runs.",
        "Find where the text comes from and review it as code.",
    ),
    Rule(
        "BS-EN-003", "obfuscation", "Decodes and runs hidden code", Level.HIGH,
        "Encoded or compressed data is decoded and executed, a common way to hide a payload "
        "from review.",
        "Do not run this. Decode the data separately and review it as its own code.",
    ),
    Rule(
        "BS-OB-001", "obfuscation", "Hides code after a long run of whitespace", Level.HIGH,
        "Code follows a long run of spaces or tabs, which pushes it off the edge of most "
        "editors and review tools. Repository-poisoning campaigns hide loaders this way.",
        "Scroll right or view the raw line, and review what is hidden there.",
    ),
    Rule(
        "BS-OB-002", "obfuscation", "Contains packed or obfuscated code", Level.REVIEW,
        "The code is packed, minified into very long lines, or carries a large encoded "
        "blob, so it cannot be reviewed as written.",
        "Find the readable source this was built from and compare the two.",
    ),
    Rule(
        "BS-UC-001", "obfuscation", "Contains invisible or direction-changing characters",
        Level.HIGH,
        "The text contains characters that do not display, or that reorder how the line is "
        "shown. What a reviewer reads can differ from what a compiler, interpreter or AI "
        "agent reads.",
        "View the file with invisible characters shown and remove any that are not needed.",
    ),
    Rule(
        "BS-EX-001", "exfiltration", "Collects secrets and can send them out", Level.HIGH,
        "Code that runs on its own both collects credentials or the environment and can "
        "reach the network. That combination is the shape of a credential stealer.",
        "Do not install or run this until the code has been reviewed by hand.",
        ("The analysis does not prove the collected data is the data that is sent.",),
    ),
)}

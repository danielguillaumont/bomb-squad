"""The import step: import each top-level module of the installed distribution once."""

import importlib
import importlib.metadata
import sys

name = sys.argv[1]
try:
    dist = importlib.metadata.distribution(name)
except importlib.metadata.PackageNotFoundError:
    print("not installed:", name)
    sys.exit(3)
tops = {line.strip() for line in (dist.read_text("top_level.txt") or "").splitlines()
        if line.strip()}
if not tops:
    for file in dist.files or []:
        head = file.parts[0] if file.parts else ""
        if head.endswith((".dist-info", ".data")) or head == "..":
            continue
        top = head[:-3] if head.endswith(".py") else head
        if top.isidentifier():
            tops.add(top)
for top in sorted(tops):
    try:
        importlib.import_module(top)
        print("imported", top)
    except BaseException as exc:  # noqa: BLE001 - any failure is only reported
        print("import failed", top, type(exc).__name__)

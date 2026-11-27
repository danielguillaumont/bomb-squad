"""Malicious samples from the DataDog malicious-software-packages-dataset.

Samples sit at `samples/<ecosystem>/<kind>/<name>/<version>/<date>-<name>-v<version>.zip`,
encrypted with the password `infected`. The date is when DataDog found the package, not
when it was published. The listing comes from `git ls-tree` on a blobless clone, so only
the selected samples are ever downloaded.
"""

from __future__ import annotations

import random
import re
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

from bombsquad.archive import ArchiveError, unpack

ECOSYSTEMS = ("npm", "pypi")
PASSWORD = b"infected"
_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})-.+\.zip$")
INNER_ARCHIVES = (".tgz", ".tar.gz", ".tar", ".whl", ".zip", ".tar.bz2")
PYTHON_MARKERS = ("setup.py", "pyproject.toml", "setup.cfg", "PKG-INFO")


@dataclass(frozen=True)
class Sample:
    ecosystem: str
    kind: str  # malicious_intent | compromised_lib
    name: str
    version: str
    discovered: str  # ISO date: when DataDog found it
    path: str  # inside the dataset
    splits: tuple[str, ...] = field(default=())

    def to_dict(self) -> dict:
        return {**asdict(self), "splits": list(self.splits)}


def parse_listing(lines: list[str]) -> list[Sample]:
    out = []
    for line in lines:
        parts = line.strip().split("/")
        if len(parts) < 6 or parts[0] != "samples" or parts[1] not in ECOSYSTEMS:
            continue
        match = _FILE.match(parts[-1])
        if not match:
            continue
        out.append(Sample(parts[1], parts[2], "/".join(parts[3:-2]), parts[-2],
                          match.group(1), line.strip()))
    return out


def select(samples: list[Sample], per_ecosystem: int, seed: int, cutoff: date,
           exclude: frozenset[tuple[str, str]] = frozenset()) -> list[Sample]:
    """One version per package name, so a campaign of near-identical versions counts once.

    `retrospective`: a seeded sample of every package. `after-cutoff`: every package found
    after the cutoff, up to the same number, for the time-split evaluation. `exclude`:
    (ecosystem, name) pairs left out, such as those earlier runs used."""
    chosen: dict[str, Sample] = {}
    splits: dict[str, set[str]] = {}
    for ecosystem in ECOSYSTEMS:
        rng = random.Random(f"{seed}:{ecosystem}")
        by_name: dict[str, list[Sample]] = {}
        for s in samples:
            if s.ecosystem == ecosystem:
                by_name.setdefault(s.name, []).append(s)
        unique = [rng.choice(sorted(group, key=lambda s: s.path))
                  for name, group in sorted(by_name.items())
                  if (ecosystem, name) not in exclude]
        for s in rng.sample(unique, min(per_ecosystem, len(unique))):
            chosen[s.path] = s
            splits.setdefault(s.path, set()).add("retrospective")
        after = [s for s in unique if date.fromisoformat(s.discovered) > cutoff]
        for s in rng.sample(after, min(per_ecosystem, len(after))):
            chosen[s.path] = s
            splits.setdefault(s.path, set()).add("after-cutoff")
    return [Sample(**{**asdict(s), "splits": tuple(sorted(splits[s.path]))})
            for s in sorted(chosen.values(), key=lambda s: s.path)]


def chosen_names(samples: list[Sample], per_ecosystem: int, seed: int
                 ) -> frozenset[tuple[str, str]]:
    """The (ecosystem, name) pairs `select` takes for the retrospective set with this seed
    and count. Recomputed from the listing, so exact only for the dataset commit the
    earlier selection used."""
    return frozenset((s.ecosystem, s.name) for s in select(samples, per_ecosystem, seed,
                                                           date.max))


def _shallowest(root: Path, names: tuple[str, ...]) -> Path | None:
    found = sorted((p.parent for name in names for p in root.rglob(name) if p.is_file()),
                   key=lambda p: (len(p.parts), str(p)))
    return found[0] if found else None


def package_root(ecosystem: str, root: Path) -> Path:
    if ecosystem == "npm":
        return _shallowest(root, ("package.json",)) or root
    return _shallowest(root, PYTHON_MARKERS) or root


def extract(sample: Sample, dataset: Path, dest: Path) -> tuple[Path, list[str]]:
    """Decrypt and unpack a sample under `dest` with the same safe unpacking as packages,
    then unpack any package archive inside it. Returns the package folder to scan."""
    data = (dataset / sample.path).read_bytes()
    root, notes = unpack(data, Path(sample.path).name, dest / "sample", PASSWORD)
    inner = [p for p in sorted(root.rglob("*")) if p.is_file()
             and p.name.lower().endswith(INNER_ARCHIVES)]
    if inner and len(inner) <= 3:
        for number, archive in enumerate(inner):
            try:
                unpacked, skipped = unpack(archive.read_bytes(), archive.name,
                                           dest / f"inner-{number}")
            except ArchiveError as exc:
                notes.append(f"{archive.name}: {exc}")
                continue
            notes += skipped
            root = unpacked if len(inner) == 1 else dest
    return package_root(sample.ecosystem, root), notes

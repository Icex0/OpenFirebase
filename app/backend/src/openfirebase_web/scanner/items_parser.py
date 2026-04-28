"""Parser for OpenFirebase's ``*_firebase_items.txt`` dump.

Used to show extracted projects + per-package item breakdown in the UI
before the full scan completes. The final ``scan.json`` overrides this
data at the end of the run.

File format (as emitted by ``openfirebase.core.orchestrator``):

    === com.example.app ===
    [Firebase_Project_ID]
    - my-project-1
    - my-project-2
    [Google_API_Key]
    - AIza...
    [...]
"""
from __future__ import annotations

import re
from pathlib import Path

_PKG_RE = re.compile(r"^===\s*(.+?)\s*===$")
_CAT_RE = re.compile(r"^\[([A-Za-z0-9_]+)\]$")
_ITEM_RE = re.compile(r"^-\s*(.+?)\s*$")

_PROJECT_ID_CATS = {"Firebase_Project_ID", "Other_Firebase_Project_ID"}

# Categories whose values are multi-line PEM blocks. The writer emits the
# first line as ``- -----BEGIN PRIVATE KEY-----`` and the body / end marker
# on subsequent unprefixed lines. Without special handling we'd capture only
# the BEGIN header.
_MULTILINE_PEM_CATS = {"Service_Account_Private_Key", "Hardcoded_Private_Key"}
_PEM_END = "-----END PRIVATE KEY-----"


def parse_items_file(path: Path) -> list[dict]:
    """Parse an items file and return a list of project dicts:

        [{"project_id": str, "package_names": [str], "extracted_items": {cat: [values]}}, ...]

    Projects are deduplicated across packages; ``package_names`` aggregates
    every package that referenced the project. ``extracted_items`` contains
    only the subset of categories that belong to this project's packages.
    """
    if not path.is_file():
        return []

    # package -> {category -> [values]}
    packages: dict[str, dict[str, list[str]]] = {}
    current_pkg: str | None = None
    current_cat: str | None = None
    # While reading a PEM body, this points at the in-progress value so we can
    # keep appending continuation lines to it.
    pending_pem: list[str] | None = None

    def _flush_pem() -> None:
        nonlocal pending_pem
        if pending_pem is None or current_pkg is None or current_cat is None:
            pending_pem = None
            return
        value = "\n".join(pending_pem)
        bucket = packages[current_pkg].setdefault(current_cat, [])
        if value and value not in bucket:
            bucket.append(value)
        pending_pem = None

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        if not line:
            # Blank lines mark the end of a package block but not a PEM body
            # (standard PEM has no blank lines internally), so flush.
            _flush_pem()
            continue
        m = _PKG_RE.match(line)
        if m:
            _flush_pem()
            current_pkg = m.group(1)
            current_cat = None
            packages.setdefault(current_pkg, {})
            continue
        if current_pkg is None:
            continue
        m = _CAT_RE.match(line)
        if m:
            _flush_pem()
            current_cat = m.group(1)
            packages[current_pkg].setdefault(current_cat, [])
            continue
        m = _ITEM_RE.match(line)
        if m and current_cat is not None:
            _flush_pem()
            value = m.group(1)
            if current_cat in _MULTILINE_PEM_CATS and value.startswith("-----BEGIN"):
                # Start of a PEM block — accumulate until we hit the END line.
                pending_pem = [value]
                if line == _PEM_END or value == _PEM_END:
                    _flush_pem()
                continue
            if value and value not in packages[current_pkg][current_cat]:
                packages[current_pkg][current_cat].append(value)
            continue
        # Continuation line for an in-progress PEM body.
        if pending_pem is not None:
            pending_pem.append(line)
            if line == _PEM_END:
                _flush_pem()

    _flush_pem()

    # Build per-project aggregates.
    projects: dict[str, dict] = {}
    for pkg, cats in packages.items():
        pids: list[str] = []
        for cat in _PROJECT_ID_CATS:
            pids.extend(cats.get(cat, []))
        for pid in pids:
            entry = projects.setdefault(
                pid,
                {"project_id": pid, "package_names": [], "extracted_items": {}},
            )
            if pkg not in entry["package_names"]:
                entry["package_names"].append(pkg)
            # Merge this package's categories into the project's item pool.
            for cat, values in cats.items():
                bucket = entry["extracted_items"].setdefault(cat, [])
                for v in values:
                    if v not in bucket:
                        bucket.append(v)

    return list(projects.values())

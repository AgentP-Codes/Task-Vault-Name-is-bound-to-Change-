"""Local files: a folder of documents, or a CSV / JSON / JSONL table."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

TEXT_SUFFIXES = {".txt", ".md", ".markdown", ".rst", ".html", ".htm", ".csv", ".json", ".yaml", ".yml"}


class FolderDocuments:
    """key = file name without extension (e.g. `refund_policy` for refund_policy.md). No path tricks."""

    def __init__(self, root: str | Path, max_bytes: int = 2_000_000):
        self.root, self.max_bytes = Path(root).resolve(), max_bytes

    def keys(self) -> list[str]:
        return sorted(p.stem for p in self.root.iterdir() if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES)

    def __call__(self, key: Any) -> dict | None:
        key = str(key)
        if not key or "/" in key or "\\" in key or key.startswith("."):
            return None
        for p in sorted(self.root.glob(f"{key}.*")):
            if p.suffix.lower() in TEXT_SUFFIXES and p.resolve().parent == self.root and p.is_file():
                if p.stat().st_size > self.max_bytes:
                    raise ValueError(f"{p.name} is larger than max_bytes")
                return {"name": p.stem, "body": p.read_text(errors="replace")}
        return None


def read_table(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as f:
            return [dict(r) for r in csv.DictReader(f)]
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    data = json.loads(path.read_text())
    if isinstance(data, dict):
        data = next((v for v in data.values() if isinstance(v, list)), [data])
    return [r for r in data if isinstance(r, dict)]


class TableFile:
    """A CSV / JSON / JSONL file as a source, keyed by one column. Re-read when the file changes."""

    def __init__(self, path: str | Path, key_column: str):
        self.path, self.key = Path(path), key_column
        self._mtime = -1.0
        self._rows: dict[str, dict[str, Any]] = {}

    def __call__(self, key: Any) -> dict | None:
        mtime = self.path.stat().st_mtime
        if mtime != self._mtime:
            self._rows = {str(r.get(self.key)): r for r in read_table(self.path)}
            self._mtime = mtime
        return self._rows.get(str(key))

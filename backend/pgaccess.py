from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

from . import handles
from .vendor.postgresql_viewer.engine.postgres import open_cluster

REGISTRY = handles.Registry("pgcluster", 2, open_cluster, lambda c: c.close())


def find_pgdata(root: Path) -> list[Path]:
    out = []
    for v in root.rglob("PG_VERSION"):
        d = v.parent
        if (d / "global" / "pg_control").is_file():
            out.append(d)
    return sorted(out, key=lambda p: len(p.parts))


def display(v) -> str | int | float | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return v if abs(v) < 2 ** 53 else str(v)
    if isinstance(v, float):
        return v if v == v else "NaN"
    if isinstance(v, (Decimal, datetime, date)):
        return str(v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        return "\\x" + b[:64].hex() + ("…" if len(b) > 64 else "")
    if isinstance(v, (dict, list, tuple)):
        import json
        try:
            return json.dumps(v, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return str(v)
    return str(v)

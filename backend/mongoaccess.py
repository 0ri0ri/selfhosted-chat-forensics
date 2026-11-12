from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

from . import handles
from .vendor.mongodb_viewer.engine.mongo import bsonlib, open_dbpath
from .vendor.mongodb_viewer.engine.mongo.bsonlib import Binary, Date, ObjectId, Timestamp

REGISTRY = handles.Registry("mongodb", 2, open_dbpath, lambda d: d.close())

MARKERS = ("WiredTiger.turtle", "WiredTiger.wt")


def find_dbpath(root: Path) -> list[Path]:
    found = sorted({t.parent for t in root.rglob(MARKERS[0]) if (t.parent / MARKERS[1]).is_file()},
                   key=lambda p: len(p.parts))
    outer = [p for p in found if not any(q != p and p.is_relative_to(q) for q in found)]
    with_catalog = [p for p in outer if (p / "_mdb_catalog.wt").is_file()]
    return with_catalog or outer


def date_str(v) -> str:
    if isinstance(v, Date):
        try:
            d = datetime(1970, 1, 1) + timedelta(milliseconds=v.ms)
            return d.strftime("%Y-%m-%d %H:%M:%S.") + f"{d.microsecond // 1000:03d}"
        except (OverflowError, ValueError):
            return str(v.ms)
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S.") + f"{v.microsecond // 1000:03d}"
    return ""


def iso_str(s) -> str:
    if not s or not isinstance(s, str):
        return ""
    return s.replace("T", " ").rstrip("Z")


def oid(v) -> str:
    if isinstance(v, ObjectId):
        return str(v)
    if isinstance(v, str):
        return v
    if v is None:
        return ""
    return bsonlib.canonical(v)


def text(v, limit: int | None = None) -> str | int | float | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return v if abs(v) < 2 ** 53 else str(v)
    if isinstance(v, float):
        return v if v == v else "NaN"
    if isinstance(v, str):
        s = v
    elif isinstance(v, Date):
        return date_str(v)
    elif isinstance(v, ObjectId):
        s = str(v)
    elif isinstance(v, Binary):
        s = f"Binary({v.subtype:02x}, {len(v.data)} B)"
    elif isinstance(v, Timestamp):
        s = f"Timestamp({v.t}, {v.i})"
    else:
        s = json.dumps(bsonlib.to_json(v, 32), ensure_ascii=False, separators=(",", ":"))
    if limit is not None and len(s) > limit:
        s = s[:limit] + "…"
    return s


def to_json(v, bin_limit: int | None = 64):
    return bsonlib.to_json(v, bin_limit)


def json_text(doc) -> str:
    return json.dumps(bsonlib.to_json(doc, 48), ensure_ascii=False, separators=(",", ":"))

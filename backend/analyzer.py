from __future__ import annotations

import hashlib
from pathlib import Path

from .apps_meta import APPS, MODES

BACKEND = Path(__file__).resolve().parent
COMMON = ["parsers/base.py", "mongoaccess.py", "pgaccess.py"]


def _files(mode: str, app: str) -> list[Path]:
    out = [BACKEND / "parsers" / mode / f"{app}.py"] + [BACKEND / p for p in COMMON]
    out += sorted((BACKEND / "artifacts").glob("*.py"))
    return out


def fingerprint(mode: str, app: str) -> str:
    h = hashlib.sha256()
    for f in _files(mode, app):
        h.update(f.relative_to(BACKEND).as_posix().encode() + b"\0")
        try:
            h.update(f.read_bytes())
        except OSError:
            h.update(b"(missing)")
        h.update(b"\0")
    return h.hexdigest()[:12]


LOADED = {(m, a): fingerprint(m, a) for m in MODES for a in APPS}


def status(mode: str, app: str, stored: str | None) -> dict:
    loaded = LOADED[(mode, app)]
    disk = fingerprint(mode, app)
    return {
        "loaded": loaded,
        "disk": disk,
        "result": stored,
        "restart_needed": disk != loaded,
        "outdated": bool(stored) and stored != loaded,
    }

from __future__ import annotations

import os
import time
from pathlib import Path

from . import handles, mongoaccess, pgaccess
from .artifacts import chromium_cache

MAX_HITS = 300
SNIP = 60
MAX_FILE = 256 * 1024**2
HIDE_SCHEMAS = ("pg_catalog", "information_schema", "pg_toast")


def _clean(s: str) -> str:
    out = []
    for ch in s:
        if ch in "\r\n\t":
            out.append(" ")
        elif ch == "\x00":
            continue
        elif ord(ch) < 32 or ch == "�" or 0x7F <= ord(ch) < 0xA0:
            out.append(".")
        else:
            out.append(ch)
    return "".join(out)


def _snippet(text: str, idx: int, qlen: int) -> dict:
    a, b = max(0, idx - SNIP), min(len(text), idx + qlen + SNIP)
    clean = _clean
    return {"before": ("…" if a else "") + clean(text[a:idx]), "match": clean(text[idx:idx + qlen]),
            "after": clean(text[idx + qlen:b]) + ("…" if b < len(text) else "")}


def _byte_pattern(q: str) -> bytes | None:
    if any(ord(ch) > 127 and ch.lower() != ch.upper() for ch in q):
        return None
    return q.lower().encode("utf-8")


def _find_text(data: bytes, q: str, pat: bytes | None) -> dict | None:
    if pat is None:
        text = data.decode("utf-8", "replace")
        i = text.lower().find(q.lower())
        return _snippet(text, i, len(q)) if i >= 0 else None
    i = data.lower().find(pat)
    if i < 0:
        return None
    a, b = max(0, i - SNIP * 4), i + len(pat) + SNIP * 4
    text = data[a:b].decode("utf-8", "replace")
    j = text.lower().find(q.lower())
    if j < 0:
        return {"before": "", "match": "", "after": f"(오프셋 {i} 에서 바이트 일치, 문맥 표시 불가)"}
    snip = _snippet(text, j, len(q))
    if a and not snip["before"].startswith("…"):
        snip["before"] = "…" + snip["before"]
    if b < len(data) and not snip["after"].endswith("…"):
        snip["after"] += "…"
    return snip


def search_pg(pgdata: Path, db_oid: int, q: str) -> dict:
    t = time.perf_counter()
    ql = q.lower()
    hits, tables, rows, truncated = [], 0, 0, False
    with pgaccess.REGISTRY.use(pgdata) as h:
        db = h.obj.database(int(db_oid))
        for rel in db.list_relations():
            if rel["kind"] not in ("r", "m", "p") or rel["schema"] in HIDE_SCHEMAS or not rel["file_size"]:
                continue
            h.check()
            tables += 1
            cols = [a["name"] for a in db.columns(rel["oid"])]
            for r in db.rows(rel["oid"]):
                rows += 1
                for name, v in zip(cols, r["values"]):
                    if v is None:
                        continue
                    s = str(pgaccess.display(v))
                    i = s.lower().find(ql)
                    if i < 0:
                        continue
                    if len(hits) >= MAX_HITS:
                        truncated = True
                        break
                    hits.append({"table": f"{rel['schema']}.{rel['name']}", "oid": rel["oid"], "rid": r["rid"],
                                 "state": r["state"], "source": r["source"], "column": name,
                                 **_snippet(s, i, len(q))})
                    break
    return {"hits": hits, "scanned": f"테이블 {tables}, 행 {rows:,}", "truncated": truncated,
            "seconds": round(time.perf_counter() - t, 2)}


def search_mongo(dbpath: Path, dbname: str, q: str) -> dict:
    t = time.perf_counter()
    ql = q.lower()
    hits, colls, rows, truncated = [], 0, 0, False
    with mongoaccess.REGISTRY.use(dbpath) as h:
        db = h.obj
        for ns in sorted(n for n in db.catalog if n.split(".", 1)[0] == dbname):
            if truncated:
                break
            h.check()
            colls += 1
            for r in db.rows(ns):
                rows += 1
                d = r.get("doc")
                if d is None:
                    continue
                s = mongoaccess.json_text(d)
                i = s.lower().find(ql)
                if i < 0:
                    continue
                if len(hits) >= MAX_HITS:
                    truncated = True
                    break
                hits.append({"table": ns, "ns": ns, "rid": r["rid"], "state": r["state"], "source": r["source"],
                             "column": "문서", **_snippet(s, i, len(q))})
    return {"hits": hits, "scanned": f"컬렉션 {colls}, 문서 {rows:,}", "truncated": truncated,
            "seconds": round(time.perf_counter() - t, 2)}


def search_cache(extracted: Path, q: str) -> dict | None:
    t = time.perf_counter()
    pat = _byte_pattern(q)
    hits, n, bad, truncated = [], 0, 0, False
    with chromium_cache.REGISTRY.use(extracted) as h:
        if h.obj is None:
            return None
        for url, keys in list(h.obj.by_url.items()):
            for key in keys:
                h.check()
                n += 1
                try:
                    with h.lock:
                        md = (h.obj.cache.get_metadata(key) or [None])[0]
                        raw = (h.obj.cache.get_cachefile(key) or [None])[0]
                    enc = ", ".join(md.get_attribute("content-encoding")) if md else ""
                    body = chromium_cache.decode_body(raw, enc)[0] if raw is not None else b""
                    ctype = ", ".join(md.get_attribute("content-type")) if md else ""
                except handles.Cancelled:
                    raise
                except Exception:
                    bad += 1
                    continue
                snip, where = _find_text(body, q, pat), "본문"
                if snip is None:
                    i = url.lower().find(q.lower())
                    if i < 0:
                        continue
                    snip, where = _snippet(url, i, len(q)), "URL"
                if len(hits) >= MAX_HITS:
                    truncated = True
                    break
                hits.append({"url": url, "key": key, "ctype": ctype, "where": where, **snip})
            if truncated:
                break
    scanned = f"캐시 엔트리 {n}" + (f" (읽기 실패 {bad})" if bad else "")
    return {"hits": hits, "scanned": scanned, "truncated": truncated, "seconds": round(time.perf_counter() - t, 2)}


def search_files(extracted: Path, q: str) -> dict:
    t = time.perf_counter()
    pats = [("UTF-8", q.lower().encode("utf-8")), ("UTF-16LE", q.lower().encode("utf-16-le"))]
    hits, n, size, truncated = [], 0, 0, False
    for dp, _, fs in os.walk(extracted):
        if chromium_cache.REGISTRY.blocked(extracted):
            raise handles.Cancelled("증거가 교체, 삭제되는 중입니다")
        for f in fs:
            p = Path(dp, f)
            try:
                st = p.stat()
                if st.st_size > MAX_FILE:
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            n += 1
            size += len(data)
            low = data.lower()
            for enc, pat in pats:
                i = low.find(pat)
                if i < 0:
                    continue
                if len(hits) >= MAX_HITS:
                    truncated = True
                    break
                a = max(0, i - SNIP * (2 if enc == "UTF-16LE" else 1))
                if enc == "UTF-16LE":
                    a -= (i - a) % 2
                chunk = data[a:i + len(pat) + SNIP * (2 if enc == "UTF-16LE" else 1)]
                text = chunk.decode("utf-16-le" if enc == "UTF-16LE" else "utf-8", "replace")
                j = text.lower().find(q.lower())
                snip = _snippet(text, j, len(q)) if j >= 0 else {"before": "", "match": q, "after": ""}
                hits.append({"path": p.relative_to(extracted).as_posix(), "size": st.st_size, "offset": i,
                             "encoding": enc, **snip})
                break
            if truncated:
                break
        if truncated:
            break
    return {"hits": hits, "scanned": f"파일 {n:,}, {size / 1e6:.1f}MB", "truncated": truncated,
            "seconds": round(time.perf_counter() - t, 2)}

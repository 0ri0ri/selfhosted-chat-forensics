import asyncio
import logging
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import analyzer, crossref, handles, mongoaccess, pgaccess, search, storage
from .artifacts import chromium_cache
from .apps_meta import APPS, MODES, get_mode_apps, is_valid
from .parsers import get_parser

log = logging.getLogger("mfa")

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"

app = FastAPI(title="Messenger Forensic Analyzer", version="0.1.0")


@app.exception_handler(handles.Busy)
@app.exception_handler(handles.Cancelled)
async def _busy_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=409, content={"detail": f"{exc} 잠시 후 다시 시도하세요."
                                                  if isinstance(exc, handles.Cancelled) else str(exc)})

SERVER_ONLY_KEYS = ("_tokens", "_old_tokens")

_slot_locks: dict[tuple[str, str, str], asyncio.Lock] = {}
_deleting_cases: set[str] = set()


def _check_target(mode: str, app_id: str) -> None:
    if not is_valid(mode, app_id):
        raise HTTPException(404, "지원하지 않는 모드 또는 애플리케이션입니다.")


def _exclusive(path: Path, fn, *args):
    with pgaccess.REGISTRY.exclusive(path), mongoaccess.REGISTRY.exclusive(path), chromium_cache.REGISTRY.exclusive(path):
        return fn(*args)


def _storage_call(fn, *args):
    try:
        return fn(*args)
    except storage.NotFoundError as e:
        raise HTTPException(404, str(e))
    except storage.StorageError as e:
        raise HTTPException(400, str(e))


@app.get("/api/modes")
def list_modes():
    return list(MODES.values())


@app.get("/api/modes/{mode}/apps")
def list_mode_apps(mode: str):
    if mode not in MODES:
        raise HTTPException(404, "지원하지 않는 모드입니다.")
    return {"mode": MODES[mode], "apps": get_mode_apps(mode)}


class CaseCreate(BaseModel):
    name: str | None = Field(default=None, max_length=100)


@app.get("/api/cases")
def list_cases(limit: int = Query(10, ge=1, le=100)):
    return storage.list_cases(limit)


@app.post("/api/cases")
def create_case(body: CaseCreate | None = None):
    name = (body.name or "").strip() if body else ""
    return storage.create_case(name or None)


@app.get("/api/cases/{case_id}")
def get_case(case_id: str):
    case = _storage_call(storage.load_case, case_id)
    return {**case, "evidences": storage.list_evidences(case_id)}


def _analyze(mode: str, app_id: str, staging: Path) -> tuple[list[dict], dict]:
    inventory = storage.safe_extract(staging / "evidence.zip", staging / "extracted")
    return inventory, get_parser(mode, app_id).run(staging / "extracted", inventory)


@app.post("/api/cases/{case_id}/{mode}/{app_id}/upload")
async def upload_evidence(request: Request, case_id: str, mode: str, app_id: str,
                          file: UploadFile = File(...)):
    _check_target(mode, app_id)
    _storage_call(storage.load_case, case_id)
    if int(request.headers.get("content-length") or 0) > storage.MAX_UPLOAD_BYTES + 1024**2:
        raise HTTPException(413, "업로드 용량 제한(4GB)을 초과했습니다.")
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "ZIP 파일만 업로드할 수 있습니다.")

    lock = _slot_locks.setdefault((case_id, mode, app_id), asyncio.Lock())
    if lock.locked():
        raise HTTPException(409, "같은 항목의 업로드가 이미 진행 중입니다.")

    async with lock:
        if case_id in _deleting_cases:
            raise HTTPException(409, "삭제 중인 케이스입니다.")
        staging = storage.new_staging(case_id)
        try:
            hashes = await storage.save_upload(file, staging / "evidence.zip")
            inventory, parsed = await run_in_threadpool(_analyze, mode, app_id, staging)
            evidence = {
                "filename": file.filename,
                **hashes,
                "file_count": len(inventory),
                "uploaded_at": storage.now_iso(),
                "analyzed_at": storage.now_iso(),
                "analyzer": analyzer.LOADED[(mode, app_id)],
            }
            result = {
                **parsed,
                "mode": mode,
                "app": app_id,
                "app_name": APPS[app_id]["name"],
                "status": "done",
                "evidence": evidence,
            }
            await run_in_threadpool(storage.save_result, staging, result)
            await run_in_threadpool(_exclusive, storage.evidence_dir(case_id, mode, app_id),
                                    storage.commit_staging, case_id, mode, app_id, staging)
        except storage.StorageError as e:
            raise HTTPException(400, str(e))
        except Exception:
            log.exception("분석 실패: case=%s %s/%s", case_id, mode, app_id)
            raise HTTPException(500, "분석 중 오류가 발생했습니다. 서버 로그를 확인하세요.")
        finally:
            await run_in_threadpool(storage.discard, staging)

    return {"mode": mode, "app": app_id, "status": "done", "evidence": evidence}


@app.get("/api/cases/{case_id}/{mode}/{app_id}/result")
def get_result(case_id: str, mode: str, app_id: str, background: BackgroundTasks):
    _check_target(mode, app_id)
    result = _storage_call(storage.load_result, case_id, mode, app_id)
    result["analyzer_status"], result["stale"] = _stale(mode, app_id, result)
    for s in result.get("sections", []):
        for r in s.get("rows", []) if s.get("type") == "table" else []:
            for k in SERVER_ONLY_KEYS:
                r.pop(k, None)
    lock = _slot_locks.get((case_id, mode, app_id))
    if not (lock and lock.locked()) and case_id not in _deleting_cases:
        background.add_task(_prewarm, case_id, mode, app_id, result.get("pg"), result.get("mongo"))
    return result


def _stale(mode: str, app_id: str, result: dict) -> tuple[dict, bool]:
    st = analyzer.status(mode, app_id, (result.get("evidence") or {}).get("analyzer"))
    return st, (bool(result.get("is_dummy", True)) != bool(get_parser(mode, app_id).is_dummy)) or st["outdated"]


@app.get("/api/cross")
def cross_apps():
    return crossref.supported()


@app.get("/api/cases/{case_id}/cross/{app_id}")
def get_cross(case_id: str, app_id: str):
    if app_id not in crossref.CROSS:
        raise HTTPException(404, "교차 분석을 지원하지 않는 앱입니다.")
    _storage_call(storage.load_case, case_id)
    busy = any((lk := _slot_locks.get((case_id, m, app_id))) and lk.locked() for m in ("client", "server"))
    if busy or case_id in _deleting_cases:
        raise HTTPException(409, "이 앱의 증거를 올리거나 다시 분석하는 중입니다. 끝난 뒤 다시 여세요.")
    sides = {}
    for mode in ("client", "server"):
        try:
            sides[mode] = storage.load_result(case_id, mode, app_id)
        except storage.NotFoundError:
            raise HTTPException(404, "Client 와 Server 증거가 모두 분석돼 있어야 교차 분석할 수 있습니다.")
        except (storage.StorageError, ValueError):
            log.exception("교차 분석: 결과 읽기 실패 case=%s %s/%s", case_id, mode, app_id)
            raise HTTPException(500, f"{mode} 분석 결과를 읽지 못했습니다. 해당 결과 화면에서 다시 분석해 보세요.")
    try:
        data = crossref.analyze(app_id, sides["client"], sides["server"])
    except Exception:
        log.exception("교차 분석 실패: case=%s %s", case_id, app_id)
        raise HTTPException(500, "교차 분석 중 오류가 발생했습니다. 서버 로그를 확인하세요.")
    info = {}
    for mode, r in sides.items():
        st, stale = _stale(mode, app_id, r)
        ev = r.get("evidence") or {}
        info[mode] = {"filename": ev.get("filename"), "sha256": ev.get("sha256"),
                      "analyzed_at": ev.get("analyzed_at") or ev.get("reanalyzed_at") or ev.get("uploaded_at"),
                      "stale": stale, "restart_needed": st.get("restart_needed", False)}
    return {"app": app_id, "app_name": APPS[app_id]["name"], **info, **data}


def _prewarm(case_id: str, mode: str, app_id: str, meta: dict | None, mongo: dict | None = None) -> None:
    try:
        base = (storage.evidence_dir(case_id, mode, app_id) / "extracted").resolve()
        if meta:
            pgdata = (base / meta["pgdata"]).resolve()
            if pgdata.is_relative_to(base) and pgdata.is_dir():
                with pgaccess.REGISTRY.use(pgdata) as h:
                    h.obj.wal()
                    h.obj.database(int(meta["db_oid"])).list_relations()
        if mongo:
            dbpath = (base / mongo["dbpath"]).resolve()
            if dbpath.is_relative_to(base) and dbpath.is_dir():
                with mongoaccess.REGISTRY.use(dbpath) as h:
                    h.obj.oplog_events()
        with chromium_cache.REGISTRY.use(base):
            pass
    except (handles.Busy, handles.Cancelled):
        pass
    except Exception:
        log.warning("원본 미리 열기 실패: case=%s %s/%s", case_id, mode, app_id, exc_info=True)


def _reanalyze(case_id: str, mode: str, app_id: str) -> dict:
    d = storage.evidence_dir(case_id, mode, app_id)
    old = storage.load_result(case_id, mode, app_id)
    ev = old["evidence"]
    zip_path, extracted = d / "evidence.zip", d / "extracted"
    if not zip_path.is_file() or not extracted.is_dir():
        raise storage.StorageError("보관된 증거 파일이 없어 다시 분석할 수 없습니다. ZIP 을 다시 올려 주세요.")
    actual = storage.file_sha256(zip_path)
    if actual != ev.get("sha256"):
        raise storage.StorageError(f"증거 원본 해시가 업로드 당시와 다릅니다 (저장값 {ev.get('sha256')}, 현재 {actual}). "
                                   "재분석을 중단합니다.")
    inventory = next((s["rows"] for s in old.get("sections", []) if s.get("id") == "inventory"), [])
    parsed = get_parser(mode, app_id).run(extracted, inventory)
    result = {
        **parsed,
        "mode": mode,
        "app": app_id,
        "app_name": APPS[app_id]["name"],
        "status": "done",
        "evidence": {**ev, "reanalyzed_at": storage.now_iso(), "analyzed_at": storage.now_iso(),
                     "analyzer": analyzer.LOADED[(mode, app_id)], "hash_verified": True},
    }
    storage.save_result(d, result)
    return result["evidence"]


@app.post("/api/cases/{case_id}/{mode}/{app_id}/reanalyze")
async def reanalyze(case_id: str, mode: str, app_id: str):
    _check_target(mode, app_id)
    _storage_call(storage.load_case, case_id)
    lock = _slot_locks.setdefault((case_id, mode, app_id), asyncio.Lock())
    if lock.locked():
        raise HTTPException(409, "같은 항목의 업로드 또는 분석이 진행 중입니다.")
    async with lock:
        if case_id in _deleting_cases:
            raise HTTPException(409, "삭제 중인 케이스입니다.")
        pgaccess.REGISTRY.forget(storage.evidence_dir(case_id, mode, app_id))
        mongoaccess.REGISTRY.forget(storage.evidence_dir(case_id, mode, app_id))
        chromium_cache.REGISTRY.forget(storage.evidence_dir(case_id, mode, app_id))
        try:
            evidence = await run_in_threadpool(_reanalyze, case_id, mode, app_id)
        except storage.NotFoundError as e:
            raise HTTPException(404, str(e))
        except storage.StorageError as e:
            raise HTTPException(400, str(e))
        except Exception:
            log.exception("재분석 실패: case=%s %s/%s", case_id, mode, app_id)
            raise HTTPException(500, "재분석 중 오류가 발생했습니다. 서버 로그를 확인하세요.")
    return {"mode": mode, "app": app_id, "status": "done", "evidence": evidence}


@app.delete("/api/cases/{case_id}")
async def delete_case(case_id: str):
    _storage_call(storage.load_case, case_id)
    busy = any(cid == case_id and lock.locked() for (cid, _, _), lock in _slot_locks.items())
    if busy or case_id in _deleting_cases:
        raise HTTPException(409, "업로드 또는 삭제가 진행 중인 케이스는 삭제할 수 없습니다.")
    _deleting_cases.add(case_id)
    try:
        await run_in_threadpool(_exclusive, storage.WORKSPACE / case_id, storage.delete_case, case_id)
    except storage.NotFoundError as e:
        raise HTTPException(404, str(e))
    except OSError:
        log.exception("케이스 삭제 실패: case=%s", case_id)
        raise HTTPException(500, "케이스 삭제 중 오류가 발생했습니다. 파일이 사용 중인지 확인하세요.")
    finally:
        _deleting_cases.discard(case_id)
        for slot in [s for s in _slot_locks if s[0] == case_id]:
            _slot_locks.pop(slot, None)
    return {"ok": True}


@app.delete("/api/cases/{case_id}/{mode}/{app_id}")
async def delete_evidence(case_id: str, mode: str, app_id: str):
    _check_target(mode, app_id)
    _storage_call(storage.load_case, case_id)
    lock = _slot_locks.setdefault((case_id, mode, app_id), asyncio.Lock())
    if lock.locked():
        raise HTTPException(409, "업로드가 진행 중인 항목은 삭제할 수 없습니다.")
    async with lock:
        try:
            await run_in_threadpool(_exclusive, storage.evidence_dir(case_id, mode, app_id),
                                    storage.delete_evidence, case_id, mode, app_id)
        except OSError:
            log.exception("삭제 실패: case=%s %s/%s", case_id, mode, app_id)
            raise HTTPException(500, "삭제 중 오류가 발생했습니다. 파일이 사용 중인지 확인하세요.")
    return {"ok": True}


def _deep_search(case_id: str, mode: str, app_id: str, q: str) -> dict:
    result = _storage_call(storage.load_result, case_id, mode, app_id)
    base = (storage.evidence_dir(case_id, mode, app_id) / "extracted").resolve()
    out = {"q": q}

    def guarded(name, fn, *args):
        try:
            r = fn(*args)
        except (handles.Busy, handles.Cancelled) as e:
            r = {"error": str(e)}
        except Exception as e:
            log.exception("원본 검색 실패(%s): case=%s %s/%s", name, case_id, mode, app_id)
            r = {"error": f"검색 중 오류 ({type(e).__name__})"}
        if r is not None:
            out[name] = r

    meta = result.get("pg")
    if meta:
        pgdata = (base / meta["pgdata"]).resolve()
        if pgdata.is_relative_to(base) and pgdata.is_dir():
            guarded("pg", search.search_pg, pgdata, meta["db_oid"], q)
    mmeta = result.get("mongo")
    if mmeta:
        dbpath = (base / mmeta["dbpath"]).resolve()
        if dbpath.is_relative_to(base) and dbpath.is_dir():
            guarded("mongo", search.search_mongo, dbpath, mmeta["db"], q)
    guarded("cache", search.search_cache, base, q)
    guarded("files", search.search_files, base, q)
    return out


@app.get("/api/cases/{case_id}/{mode}/{app_id}/search")
async def deep_search(case_id: str, mode: str, app_id: str, q: str = Query(..., min_length=1, max_length=200)):
    _check_target(mode, app_id)
    try:
        return await run_in_threadpool(_deep_search, case_id, mode, app_id, q)
    except HTTPException:
        raise
    except Exception:
        log.exception("원본 검색 실패: case=%s %s/%s", case_id, mode, app_id)
        raise HTTPException(500, "원본 검색 중 오류가 발생했습니다. 서버 로그를 확인하세요.")


def _cache_lookup(case_id: str, mode: str, app_id: str, url: str, key: str | None = None) -> dict:
    _storage_call(storage.load_result, case_id, mode, app_id)
    extracted = storage.evidence_dir(case_id, mode, app_id) / "extracted"
    try:
        return chromium_cache.lookup(extracted, url, key)
    except (FileNotFoundError, KeyError) as e:
        raise HTTPException(404, str(e).strip("'\""))


def _fmt_dt(dt) -> str:
    return dt.isoformat(sep=" ", timespec="milliseconds") if dt else ""


@app.get("/api/cases/{case_id}/{mode}/{app_id}/cache/meta")
async def cache_meta(case_id: str, mode: str, app_id: str, url: str, key: str | None = None):
    _check_target(mode, app_id)
    c = await run_in_threadpool(_cache_lookup, case_id, mode, app_id, url, key)
    body = c["body"]
    kind = chromium_cache.classify(c["ctype"], body)
    out = {
        "url": c["url"], "key": c["key"], "status": c["status"], "headers": c["headers"],
        "ctype": c["ctype"], "encoding": c["encoding"], "note": c["note"], "location": c["location"],
        "created": _fmt_dt(c["created"]), "request_time": _fmt_dt(c["request_time"]),
        "response_time": _fmt_dt(c["response_time"]), "raw_size": c["raw_size"],
        "size": len(body) if body is not None else None, "kind": kind,
    }
    if kind == "text":
        out["text"] = body[:chromium_cache.TEXT_LIMIT].decode("utf-8", "replace")
        out["truncated"] = len(body) > chromium_cache.TEXT_LIMIT
    elif body:
        out["hex"] = body[:2048].hex()
    return out


@app.get("/api/cases/{case_id}/{mode}/{app_id}/cache/body")
async def cache_body(case_id: str, mode: str, app_id: str, url: str, key: str | None = None, download: bool = False):
    _check_target(mode, app_id)
    c = await run_in_threadpool(_cache_lookup, case_id, mode, app_id, url, key)
    body = c["body"] or b""
    base = (c["ctype"] or "").split(";")[0].strip().lower()
    inline = base in chromium_cache.SAFE_IMAGE_TYPES and not download
    name = (url.split("?")[0].rstrip("/").rsplit("/", 1)[-1] or "cache_body")[:120]
    name = "".join(ch if (ch.isascii() and ch.isalnum()) or ch in "._-" else "_" for ch in name) or "cache_body"
    return Response(
        content=body,
        media_type=base if inline else "application/octet-stream",
        headers={
            "Content-Disposition": f'{"inline" if inline else "attachment"}; filename="{name}"',
            "Content-Security-Policy": "sandbox; default-src 'none'",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


PG_STATES = ("live", "deleted", "updated", "aborted", "in_progress", "unknown")


@contextmanager
def _pg_db(case_id: str, mode: str, app_id: str, db_oid: int | None):
    result = _storage_call(storage.load_result, case_id, mode, app_id)
    meta = result.get("pg")
    if not meta:
        raise HTTPException(404, "이 증거에는 PostgreSQL 데이터가 없습니다.")
    base = (storage.evidence_dir(case_id, mode, app_id) / "extracted").resolve()
    pgdata = (base / meta["pgdata"]).resolve()
    if not pgdata.is_relative_to(base) or not pgdata.is_dir():
        raise HTTPException(404, "PostgreSQL 데이터 디렉터리를 찾을 수 없습니다.")
    oid = db_oid if db_oid is not None else meta.get("db_oid")
    with pgaccess.REGISTRY.use(pgdata) as h:
        c = h.obj
        try:
            db = c.database(int(oid))
        except (KeyError, ValueError):
            raise HTTPException(404, f"데이터베이스 {oid} 를 찾을 수 없습니다.")
        yield c, db, meta


def _pg_tables(case_id, mode, app_id, db_oid, system):
    with _pg_db(case_id, mode, app_id, db_oid) as (c, db, meta):
        hide = ("pg_catalog", "information_schema", "pg_toast")
        tables = [{"oid": r["oid"], "schema": r["schema"], "name": r["name"], "kind": r["kind_name"],
                   "file_size": r["file_size"]}
                  for r in db.list_relations()
                  if r["kind"] in ("r", "m", "p") and (system or not (r["schema"] in hide or r["schema"].startswith("pg_temp")))]
        dbs = [{"oid": d["oid"], "name": d["name"]} for d in c.databases() if d["has_dir"] and not d.get("is_template")]
        return {"db_oid": db.oid, "databases": dbs, "tables": tables, "pg_version": c.pg_version}


def _pg_rows(case_id, mode, app_id, db_oid, rel_oid, offset, limit, q, states):
    with _pg_db(case_id, mode, app_id, db_oid) as (c, db, meta):
        try:
            rel = db.relation(rel_oid)
        except KeyError:
            raise HTTPException(404, "테이블을 찾을 수 없습니다.")
        cols = db.columns(rel_oid)
        try:
            rows = db.rows(rel_oid)
        except ValueError as e:
            raise HTTPException(400, str(e))
        by_state = {}
        for r in rows:
            by_state[r["state"]] = by_state.get(r["state"], 0) + 1
        want = set(states.split(",")) if states else set(PG_STATES)
        sel = [r for r in rows if r["state"] in want]
        if q:
            ql = q.lower()
            sel = [r for r in sel if any(v is not None and ql in str(v).lower() for v in r["values"])]
        page = sel[offset:offset + limit]
        return {
            "table": f"{rel.nsp}.{rel.name}", "path": rel.path,
            "columns": [{"name": x["name"], "type": x["type"], "dropped": x["dropped"]} for x in cols],
            "by_state": by_state, "total": len(rows), "matched": len(sel),
            "rows": [{"rid": r["rid"], "state": r["state"], "source": r["source"],
                      "xmin_time": r.get("xmin_time") or "", "xmax_time": r.get("xmax_time") or "",
                      "values": [pgaccess.display(v) for v in r["values"]],
                      "errors": r.get("errors") or {}} for r in page],
        }


@app.get("/api/cases/{case_id}/{mode}/{app_id}/pg/tables")
async def pg_tables(case_id: str, mode: str, app_id: str, db: int | None = None, system: bool = False):
    _check_target(mode, app_id)
    try:
        return await run_in_threadpool(_pg_tables, case_id, mode, app_id, db, system)
    except HTTPException:
        raise
    except Exception:
        log.exception("PG 테이블 목록 실패")
        raise HTTPException(500, "PostgreSQL 테이블 목록을 읽지 못했습니다. 서버 로그를 확인하세요.")


@app.get("/api/cases/{case_id}/{mode}/{app_id}/pg/rows")
async def pg_rows(case_id: str, mode: str, app_id: str, rel: int, db: int | None = None,
                  offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000),
                  q: str = "", states: str = ""):
    _check_target(mode, app_id)
    try:
        return await run_in_threadpool(_pg_rows, case_id, mode, app_id, db, rel, offset, limit, q, states)
    except HTTPException:
        raise
    except Exception:
        log.exception("PG 행 조회 실패")
        raise HTTPException(500, "PostgreSQL 행을 읽지 못했습니다. 서버 로그를 확인하세요.")


MONGO_STATES = ("live", "deleted", "updated", "unknown")
SYSTEM_DBS = ("admin", "local", "config")


@contextmanager
def _mongo_db(case_id: str, mode: str, app_id: str):
    result = _storage_call(storage.load_result, case_id, mode, app_id)
    meta = result.get("mongo")
    if not meta:
        raise HTTPException(404, "이 증거에는 MongoDB 데이터가 없습니다.")
    base = (storage.evidence_dir(case_id, mode, app_id) / "extracted").resolve()
    dbpath = (base / meta["dbpath"]).resolve()
    if not dbpath.is_relative_to(base) or not dbpath.is_dir():
        raise HTTPException(404, "MongoDB 데이터 디렉터리를 찾을 수 없습니다.")
    with mongoaccess.REGISTRY.use(dbpath) as h:
        yield h.obj, meta


def _mongo_collections(case_id, mode, app_id, dbname, system):
    with _mongo_db(case_id, mode, app_id) as (db, meta):
        all_dbs = db.databases()
        name = dbname if dbname in {d["name"] for d in all_dbs} else meta.get("db")
        dbs = [d for d in all_dbs if system or d["name"] not in SYSTEM_DBS or d["name"] == name]
        colls = [{"ns": c["ns"], "name": c["name"], "count": c["count"], "file_size": c["file_size"], "gridfs": c["gridfs"],
                  "capped": c["capped"]}
                 for c in db.collections(name) if system or not c["system"]]
        return {"db": name, "databases": [{"name": d["name"], "collections": d["collections"], "documents": d["documents"]}
                                          for d in dbs],
                "collections": colls, "wiredtiger": db.turtle.get("WiredTiger version string", "")}


def _mongo_rows(case_id, mode, app_id, ns, offset, limit, q, states):
    with _mongo_db(case_id, mode, app_id) as (db, meta):
        if ns not in db.catalog:
            raise HTTPException(404, "컬렉션을 찾을 수 없습니다.")
        rows = db.rows(ns)
        by_state = {}
        for r in rows:
            by_state[r["state"]] = by_state.get(r["state"], 0) + 1
        want = set(states.split(",")) if states else set(MONGO_STATES)
        sel = [r for r in rows if r["state"] in want]
        if q:
            ql = q.lower()
            sel = [r for r in sel if r.get("doc") is not None and ql in mongoaccess.json_text(r["doc"]).lower()]
        fields = [f["name"] for f in db.fields(ns, rows)][:60]
        page = sel[offset:offset + limit]
        c = db.catalog[ns]
        return {
            "ns": ns, "file": f"{c['ident']}.wt", "columns": fields, "by_state": by_state, "total": len(rows), "matched": len(sel),
            "rows": [{"rid": r["rid"], "state": r["state"], "source": r["source"], "also_in": r.get("also_in") or [],
                      "created": mongoaccess.iso_str(r.get("created") or r.get("oid_time")),
                      "deleted_at": mongoaccess.iso_str(r.get("deleted_at")), "vtime": mongoaccess.iso_str(r.get("vtime")),
                      "note": (r.get("note") or r.get("problem") or "").replace("\u2014", "-"),
                      "values": [mongoaccess.text(r["doc"].get(f), 300) if isinstance(r.get("doc"), dict) and f in r["doc"] else None
                                 for f in fields],
                      "json": mongoaccess.to_json(r["doc"], 256) if r.get("doc") is not None else None} for r in page],
        }


@app.get("/api/cases/{case_id}/{mode}/{app_id}/mongo/collections")
async def mongo_collections(case_id: str, mode: str, app_id: str, db: str = "", system: bool = False):
    _check_target(mode, app_id)
    try:
        return await run_in_threadpool(_mongo_collections, case_id, mode, app_id, db, system)
    except HTTPException:
        raise
    except Exception:
        log.exception("MongoDB 컬렉션 목록 실패")
        raise HTTPException(500, "MongoDB 컬렉션 목록을 읽지 못했습니다. 서버 로그를 확인하세요.")


@app.get("/api/cases/{case_id}/{mode}/{app_id}/mongo/rows")
async def mongo_rows(case_id: str, mode: str, app_id: str, ns: str = Query(..., min_length=3, max_length=300),
                     offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000), q: str = "", states: str = ""):
    _check_target(mode, app_id)
    try:
        return await run_in_threadpool(_mongo_rows, case_id, mode, app_id, ns, offset, limit, q, states)
    except HTTPException:
        raise
    except Exception:
        log.exception("MongoDB 문서 조회 실패")
        raise HTTPException(500, "MongoDB 문서를 읽지 못했습니다. 서버 로그를 확인하세요.")


def _mongo_gridfs(case_id, mode, app_id, bucket, key):
    with _mongo_db(case_id, mode, app_id) as (db, meta):
        if bucket + ".files" not in db.catalog or bucket + ".chunks" not in db.catalog:
            raise HTTPException(404, "GridFS 버킷을 찾을 수 없습니다.")
        try:
            return db.gridfs_data(bucket, key)
        except KeyError:
            raise HTTPException(404, "GridFS 파일을 찾을 수 없습니다.")


@app.get("/api/cases/{case_id}/{mode}/{app_id}/mongo/gridfs")
async def mongo_gridfs(case_id: str, mode: str, app_id: str, bucket: str = Query(..., max_length=300),
                       key: str = Query(..., max_length=500), name: str = Query("", max_length=200)):
    _check_target(mode, app_id)
    try:
        data, f = await run_in_threadpool(_mongo_gridfs, case_id, mode, app_id, bucket, key)
    except HTTPException:
        raise
    except Exception:
        log.exception("GridFS 내려받기 실패")
        raise HTTPException(500, "GridFS 파일을 조립하지 못했습니다. 서버 로그를 확인하세요.")
    fname = str(name or f.get("name") or f.get("filename") or "gridfs_file")[:120]
    safe = "".join(ch if (ch.isascii() and ch.isalnum()) or ch in "._-" else "_" for ch in fname) or "gridfs_file"
    if not f.get("complete"):
        safe = "INCOMPLETE_" + safe
    return Response(content=data, media_type="application/octet-stream", headers={
        "Content-Disposition": f"attachment; filename=\"{safe}\"; filename*=UTF-8''{quote(('INCOMPLETE_' if not f.get('complete') else '') + fname, safe='', errors='replace')}",
        "Content-Security-Policy": "sandbox; default-src 'none'", "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store", "X-Gridfs-Sha256": f.get("sha256") or ""})


app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")

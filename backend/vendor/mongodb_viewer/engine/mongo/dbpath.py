"""MongoDB dbPath 해석 - 공개 API.

    from mongoviewer.engine.mongo import open_dbpath
    db = open_dbpath(r"C:\\cases\\mongodb_data.zip")
    db.databases(); db.collections("rocketchat"); db.rows("rocketchat.rocketchat_message")

메타데이터 사슬: WiredTiger.turtle → WiredTiger.wt(file:/table: 설정, 체크포인트) → _mdb_catalog.wt(ns ↔ ident)
→ collection-*.wt (key = RecordId, value = BSON). sizeStorer.wt 는 컬렉션별 문서 수와 크기.

문서 출처(source)
  file   : 마지막 체크포인트 루트에서 닿는 리프 페이지의 값 (현재 문서)
  stale  : 파일 안에 남아 있지만 체크포인트에서 닿지 않는 블록의 값 (이전 체크포인트의 페이지)
  hs     : 히스토리 스토어(WiredTigerHS.wt)에 남은 이전 버전
  oplog  : oplog 의 insert/update 를 차례로 적용해 재구성한 버전
문서 상태(state)
  live    : 현재 문서
  deleted : 현재 파일에 _id 가 없는 문서 (oplog 삭제 기록이 있으면 삭제 시각을 붙인다)
  updated : 같은 _id 의 현재 문서와 내용이 다른 이전 버전
  unknown : 판단 근거 부족 (예: oplog 재구성 결과가 현재 문서와 다름)
같은 내용(정규화 JSON 일치)의 문서는 file → hs → stale → oplog 순으로 하나만 남긴다.
"""

from __future__ import annotations

import collections
import datetime as _dt
import hashlib
import json
import re
import threading
import uuid as _uuid

from . import bsonlib
from .bsonlib import Binary, Date, ObjectId, Timestamp, canonical
from .intpack import unpack_format
from .oplog import flatten, versions_by_id
from .wtfile import WTError, WTFile, cfg_value, checkpoints, record_id
from ...source import Source, open_source

SOURCE_ORDER = {"file": 0, "hs": 1, "stale": 2, "oplog": 3}
IDENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-]*(/[A-Za-z0-9_][A-Za-z0-9_\-]*)?$")   # collection-<uuid>, db/collection-..
WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))}
UPDATE_TYPES = {0: "invalid", 1: "modify", 2: "reserve", 3: "standard", 4: "tombstone"}


def ts_iso(sec: int | None) -> str | None:
    if sec is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(sec, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def ms_iso(ms: int | None) -> str | None:
    return Date(ms).iso() if ms is not None else None


def wt_ts(v: int | None):
    """WiredTiger 타임스탬프 = MongoDB Timestamp (상위 32비트 초, 하위 32비트 증가값)."""
    if v is None or v >= (1 << 64) - 1:
        return None
    return {"t": v >> 32, "i": v & 0xFFFFFFFF, "iso": ts_iso(v >> 32)}


class DbPath:
    def __init__(self, source: Source):
        self.source = source
        self._lock = threading.RLock()
        self._tables: dict[str, WTFile] = {}
        self._rows: dict[str, list[dict]] = {}
        self._oplog = None
        self._hs = None
        t = source.read("WiredTiger.turtle").decode("utf-8", "replace").split("\n")
        self.turtle = {t[i]: t[i + 1] for i in range(0, len(t) - 1, 2)}
        if "file:WiredTiger.wt" not in self.turtle:
            raise WTError("WiredTiger.turtle 에 file:WiredTiger.wt 항목이 없음")
        self.metadata = self._read_metadata()
        self.catalog = self._read_catalog()
        self.sizes = self._read_sizes()

    # ------------------------------------------------------------------ 메타데이터
    def _live(self, wf: WTFile):
        cks = checkpoints(wf.config)
        if not cks:
            return [], None
        ck = wf.checkpoint(cks[-1]["addr"])
        if not ck["root"]:
            return [], ck
        rows = []
        for off, h, img in wf.walk(ck["root"]):
            if h["type"] == 7:
                for r in wf.leaf_rows(img):
                    r["block"] = off
                    rows.append(r)
        return rows, ck

    @staticmethod
    def _visible(r) -> bool:
        """체크포인트 시점에 이미 삭제, 교체된 값(셀 시간 창에 stop 이 있음)은 메타데이터에서 쓰지 않는다."""
        tw = (r.get("cell") or {}).get("tw") or {}
        return "stop_ts" not in tw and "stop_txn" not in tw

    def _read_metadata(self) -> dict:
        cfg = self.turtle["file:WiredTiger.wt"]
        wf = WTFile("WiredTiger.wt", self.source.read("WiredTiger.wt"), cfg)
        self._tables["WiredTiger"] = wf
        md = {}
        rows, self.meta_ckpt = self._live(wf)
        for r in rows:
            if r["key"] is not None and r["value"] is not None and self._visible(r):
                md[r["key"].rstrip(b"\0").decode("utf-8", "replace")] = r["value"].rstrip(b"\0").decode("utf-8", "replace")
        return md

    def table(self, ident: str) -> WTFile:
        with self._lock:
            wf = self._tables.get(ident)
            if wf is None:
                if not isinstance(ident, str) or not IDENT_RE.match(ident) or ident.split(".")[0].upper() in WIN_RESERVED:
                    raise KeyError(f"허용하지 않는 ident: {ident!r}")
                cfg = self.metadata.get(f"file:{ident}.wt")
                if cfg is None:
                    raise KeyError(f"메타데이터에 file:{ident}.wt 가 없음")
                wf = WTFile(f"{ident}.wt", self.source.read(f"{ident}.wt"), cfg)
                self._tables[ident] = wf
            return wf

    def _read_catalog(self) -> dict:
        out = {}
        rows, _ = self._live(self.table("_mdb_catalog"))
        self.catalog_problems = []
        for r in rows:
            if r["value"] is None or not self._visible(r):
                continue
            try:
                d = bsonlib.decode(r["value"])
            except bsonlib.BSONError as e:
                self.catalog_problems.append(f"카탈로그 항목 해석 실패: {e}")
                continue
            md = d.get("md") or {}
            ns = d.get("ns") or md.get("ns")
            if not ns:
                continue
            opts = md.get("options") or {}
            if ns in out:
                self.catalog_problems.append(f"카탈로그에 같은 ns 가 여러 번: {ns}")
            u = opts.get("uuid")
            out[ns] = {"ns": ns, "ident": d.get("ident"), "catalog_id": record_id(r["key"]),
                       "idx_ident": d.get("idxIdent") or {}, "indexes": [
                           {"name": (i.get("spec") or {}).get("name"), "key": bsonlib.to_json((i.get("spec") or {}).get("key")),
                            "unique": bool((i.get("spec") or {}).get("unique")), "ready": i.get("ready")}
                           for i in (md.get("indexes") or []) if isinstance(i, dict)],
                       "uuid": str(_uuid.UUID(bytes=u.data)) if isinstance(u, Binary) and len(u.data) == 16 else None,
                       "capped": bool(opts.get("capped")), "view_on": opts.get("viewOn"),
                       "timeseries": bool(opts.get("timeseries"))}
        return out

    def _read_sizes(self) -> dict:
        out = {}
        try:
            rows, _ = self._live(self.table("sizeStorer"))
        except (KeyError, WTError):
            return out
        for r in rows:
            if r["key"] is None or not r["value"] or not self._visible(r):
                continue
            try:
                out[r["key"].rstrip(b"\0").decode("utf-8", "replace")] = bsonlib.decode(r["value"])
            except bsonlib.BSONError:
                pass
        return out

    # ------------------------------------------------------------------ 목록
    def databases(self) -> list[dict]:
        agg = collections.OrderedDict()
        for ns in sorted(self.catalog):
            dbn = ns.split(".", 1)[0]
            a = agg.setdefault(dbn, {"name": dbn, "collections": 0, "documents": 0, "bytes": 0})
            a["collections"] += 1
            s = self.sizes.get(f"table:{self.catalog[ns]['ident']}") or {}
            a["documents"] += int(s.get("numRecords") or 0)
            a["bytes"] += int(s.get("dataSize") or 0)
        return list(agg.values())

    def collections(self, dbname: str) -> list[dict]:
        out = []
        for ns, c in sorted(self.catalog.items()):
            if ns.split(".", 1)[0] != dbname:
                continue
            s = self.sizes.get(f"table:{c['ident']}") or {}
            fn = f"{c['ident']}.wt"
            name = ns.split(".", 1)[-1]
            out.append({"ns": ns, "name": name, "ident": c["ident"],
                        "file": fn, "file_size": self.source.size(fn) if self.source.exists(fn) else None,
                        "count": s.get("numRecords"), "data_size": s.get("dataSize"),
                        "indexes": len(c["indexes"]), "capped": c["capped"], "view_on": c["view_on"],
                        "system": name.startswith("system."),
                        "gridfs": "files" if ns.endswith(".files") and ns[:-6] + ".chunks" in self.catalog
                        else "chunks" if ns.endswith(".chunks") and ns[:-7] + ".files" in self.catalog else None})
        return out

    # ------------------------------------------------------------------ oplog, 히스토리 스토어
    def oplog_events(self) -> list[dict]:
        with self._lock:
            if self._oplog is None:
                c = self.catalog.get("local.oplog.rs")
                if not c:
                    self._oplog = []
                else:
                    entries = []
                    rows, _ = self._live(self.table(c["ident"]))
                    self.oplog_problems = 0
                    for r in rows:
                        if r["value"] is None or r["key"] is None:
                            continue
                        try:
                            entries.append((record_id(r["key"]), bsonlib.decode(r["value"])))
                        except bsonlib.BSONError:
                            self.oplog_problems += 1
                    self._oplog = flatten(entries)
            return self._oplog

    def oplog_summary(self) -> dict:
        evs = self.oplog_events()
        if not evs:
            return {"available": "local.oplog.rs" in self.catalog, "entries": 0}
        walls = [e["wall"] for e in evs if e["wall"] is not None]
        tss = [e["ts"] for e in evs if e["ts"]]
        by = collections.Counter((e["ns"] or "", e["op"] or "") for e in evs)
        return {"available": True, "entries": len({e["recordId"] for e in evs}), "operations": len(evs),
                "first_ts": {"t": tss[0][0], "i": tss[0][1], "iso": ts_iso(tss[0][0])} if tss else None,
                "last_ts": {"t": tss[-1][0], "i": tss[-1][1], "iso": ts_iso(tss[-1][0])} if tss else None,
                "first_wall": ms_iso(min(walls)) if walls else None, "last_wall": ms_iso(max(walls)) if walls else None,
                "by_ns_op": [{"ns": ns, "op": op, "count": n} for (ns, op), n in sorted(by.items())]}

    def history_store(self) -> dict:
        """btree id → [{key, start_ts, counter, stop_durable_ts, durable_ts, type, value, tw}]"""
        with self._lock:
            if self._hs is None:
                hs = collections.defaultdict(list)    # 다 채운 뒤에 대입한다 (중간 실패가 빈 값으로 굳지 않게)
                self.hs_problems = []
                try:
                    rows, _ = self._live(self.table("WiredTigerHS"))
                except KeyError:
                    rows = []
                except Exception as e:
                    self.hs_problems.append(f"히스토리 스토어를 읽지 못함: {type(e).__name__}: {e}")
                    rows = []
                for r in rows:
                    if r["key"] is None or r["value"] is None:
                        continue
                    try:
                        bid, ukey, start_ts, counter = unpack_format("IuQQ", r["key"])
                        stop_d, dur, utype, val = unpack_format("QQQu", r["value"])
                    except Exception as e:
                        self.hs_problems.append(f"히스토리 스토어 항목 해석 실패 (블록 {r['block']}): {e}")
                        continue
                    hs[bid].append({"key": ukey, "start_ts": start_ts, "counter": counter, "stop_durable_ts": stop_d,
                                          "durable_ts": dur, "type": utype, "value": val,
                                          "tw": (r.get("cell") or {}).get("tw") or {}, "block": r["block"]})
                self._hs = hs
            return self._hs

    # ------------------------------------------------------------------ 문서
    def _btree_id(self, ident: str) -> int | None:
        v = cfg_value(self.metadata.get(f"file:{ident}.wt", ""), "id")
        return int(v) if v and v.isdigit() else None

    def rows(self, ns: str) -> list[dict]:
        with self._lock:
            if ns in self._rows:
                return self._rows[ns]
        if ns not in self.catalog:
            raise KeyError(f"컬렉션 없음: {ns}")
        c = self.catalog[ns]
        wf = self.table(c["ident"])
        out: list[dict] = []
        seen: dict[str, dict] = {}          # canonical 문서 → 대표 행

        def add(row):
            # 다른 출처의 같은 내용만 합친다. 같은 출처 안의 동일 문서(_id 없는 컬렉션 등)는 모두 남긴다.
            key = row.get("canon")
            if key is not None and key in seen and seen[key]["source"] != row["source"]:
                rep = seen[key]
                rep.setdefault("also_in", [])
                if row["source"] not in rep["also_in"]:
                    rep["also_in"].append(row["source"])
                return False
            if key is not None:
                seen[key] = row
            out.append(row)
            return True

        def decode_row(val, base):
            try:
                doc = bsonlib.decode(val)
                return {**base, "doc": doc, "raw": val, "canon": canonical(doc), "problem": None}
            except bsonlib.BSONError as e:
                return {**base, "doc": None, "raw": val, "canon": None, "problem": f"BSON 해석 실패: {e}"}

        problems = []
        # 1) 현재 파일 - 트리가 손상돼도 아래의 끊긴 블록 스캔은 계속한다
        live_blocks = set()
        try:
            live_rows, ck = self._live(wf)
            if ck and ck["root"]:
                live_blocks = {off for off, _, _ in wf.walk(ck["root"])}
        except Exception as e:
            live_rows = []
            problems.append({"offset": None, "problem": f"체크포인트 트리를 읽지 못함: {type(e).__name__}: {e}"})
        for r in live_rows:
            vc = r.get("value_cell") or {}
            tw = (r.get("cell") or {}).get("tw") or {}
            rec = record_id(r["key"])
            base = {"source": "file", "rid": f"f:{rec}" if rec is not None else f"f?:{r['block']}:{(r.get('key_cell') or {}).get('off')}",
                    "record_id": rec, "block": r["block"],
                    "cell_off": (r.get("cell") or {}).get("off"), "value_off": vc.get("data_off"), "tw": tw}
            if r["value"] is None:
                out.append({**base, "doc": None, "raw": None, "canon": None, "problem": r["problem"], "state": "unknown"})
                continue
            row = decode_row(r["value"], base)
            row["state"] = "deleted" if ("stop_ts" in tw or "stop_txn" in tw) else "live"
            if row["state"] == "deleted":
                row["note"] = "셀에 종료 시간 창(stop)이 있음 - 체크포인트 시점에 이미 삭제, 교체된 값"
            add(row)
        live_ids = {canonical(r["doc"].get("_id")) for r in out if r["doc"] is not None and r["state"] == "live"}

        # 2) 히스토리 스토어
        bid = self._btree_id(c["ident"])
        for k, h in enumerate(self.history_store().get(bid, []) if bid is not None else []):
            base = {"source": "hs", "rid": f"h:{k}", "record_id": record_id(h["key"]),
                    "block": h["block"], "hs": {"start_ts": wt_ts(h["start_ts"]), "stop_durable_ts": wt_ts(h["stop_durable_ts"]),
                                                "durable_ts": wt_ts(h["durable_ts"]), "counter": h["counter"],
                                                "type": UPDATE_TYPES.get(h["type"], h["type"])}, "tw": h["tw"]}
            if h["type"] != 3:
                out.append({**base, "doc": None, "raw": h["value"], "canon": None, "state": "unknown",
                            "problem": f"히스토리 스토어 값 형식 {UPDATE_TYPES.get(h['type'], h['type'])} - BSON 이 아니라 해석하지 않음"})
                continue
            add(decode_row(h["value"], base))

        # 3) 끊긴 블록
        blocks, sp = wf.scan()
        problems.extend(sp)
        for off, h, img in blocks:
            if off in live_blocks or h["type"] != 7:
                continue
            try:
                lrows = wf.leaf_rows(img)
            except Exception as e:
                problems.append({"offset": off, "problem": f"셀 해석 실패: {e}"})
                continue
            for j, r in enumerate(lrows):
                if r["value"] is None:
                    continue
                vc = r.get("value_cell") or {}
                base = {"source": "stale", "rid": f"s:{off}:{j}", "record_id": record_id(r["key"]),
                        "block": off, "cell_off": (r.get("cell") or {}).get("off"), "value_off": vc.get("data_off"),
                        "tw": (r.get("cell") or {}).get("tw") or {}}
                add(decode_row(r["value"], base))

        # 4) oplog 재구성
        evs = [e for e in self.oplog_events() if e["ns"] == ns]
        hist = versions_by_id(evs) if evs else {}
        times = {}
        for key, st in hist.items():
            times[key] = {"created": st["inserted"]["wall"] if st["inserted"] else None,
                          "deleted": st["deleted"]["wall"] if st["deleted"] else None,
                          "updated": max((v["ev"]["wall"] or 0 for v in st["versions"] if v["kind"] == "update"), default=None),
                          "problem": st["problem"], "events": len(st["events"])}
            for n, v in enumerate(st["versions"]):
                doc = v["doc"]
                last = n == len(st["versions"]) - 1
                row = {"source": "oplog", "rid": f"o:{v['ev']['recordId']}:{v['ev']['sub'] if v['ev']['sub'] is not None else ''}",
                       "record_id": None, "doc": doc, "raw": None, "canon": canonical(doc), "problem": None,
                       "oplog": {"ts": v["ev"]["ts"], "wall": ms_iso(v["ev"]["wall"]), "kind": v["kind"],
                                 "recordId": v["ev"]["recordId"], "version": n + 1, "versions": len(st["versions"])}}
                if not add(row):
                    continue                     # 같은 내용이 이미 다른 출처에 있다
                if key in live_ids:
                    if last and not st["deleted"]:
                        row["state"] = "unknown"
                        row["note"] = "oplog 재구성 마지막 버전이 현재 문서와 다름 (재구성 한계일 수 있음)"
                    else:
                        row["state"] = "updated"
                else:
                    row["state"] = "deleted"
                    if not st["deleted"]:
                        row["note"] = "현재 파일에 없지만 oplog 에 삭제 기록도 없음 (다른 경로로 정리됐을 수 있음)"
        # 상태 마무리 (file 외 출처)
        for row in out:
            if row["source"] == "file" or "state" in row:
                continue
            d = row.get("doc")
            k = canonical(d.get("_id")) if isinstance(d, dict) else None
            row["state"] = "updated" if k in live_ids else "deleted"
        # 시각, 이력
        chains = collections.defaultdict(list)
        for row in out:
            d = row.get("doc")
            k = canonical(d.get("_id")) if isinstance(d, dict) and "_id" in d else None
            row["id_key"] = k
            t = times.get(k) if k else None
            row["created"] = ms_iso(t["created"]) if t and t["created"] else None
            row["deleted_at"] = ms_iso(t["deleted"]) if t and t["deleted"] else None
            if t and t["problem"]:
                row.setdefault("note", "oplog 재구성 중단: " + t["problem"])
            if isinstance(d, dict) and isinstance(d.get("_id"), ObjectId) and not row["created"]:
                row["oid_time"] = ts_iso(d["_id"].time())
            row["vtime"] = self._vtime(row)
            if k:
                chains[k].append(row)
        cid = 0
        for k, rs in chains.items():
            if len(rs) < 2:
                continue
            cid += 1
            # 현재 문서는 맨 뒤, 시각을 모르는 옛 버전(끊긴 블록 등)은 맨 앞, 나머지는 시각순 (문자열이 아니라 시각으로 비교)
            rs.sort(key=lambda r: (r["state"] == "live", r["vtime"] is not None, iso_epoch(r["vtime"])))
            # 현재 파일에 없는(삭제된) 문서: 삭제된 것은 마지막 버전 하나이고, 앞의 버전들은 그 문서의 이전 버전이다
            if not any(r["state"] == "live" for r in rs):
                for r in rs[:-1]:
                    if r["state"] == "deleted":
                        r["state"] = "updated"
            for i, r in enumerate(rs, 1):
                r["chain"] = {"id": cid, "pos": i, "len": len(rs)}
        out.sort(key=lambda r: (SOURCE_ORDER.get(r["source"], 9) != 0, r["record_id"] if r["record_id"] is not None else 1 << 62,
                                SOURCE_ORDER.get(r["source"], 9), r["rid"]))
        for r in out:
            r.setdefault("problem", None)
        stats = {"problems": problems}
        with self._lock:
            self._rows[ns] = out
            self._rows["__stats__" + ns] = stats
        return out

    @staticmethod
    def _vtime(row):
        if row["source"] == "oplog":
            return row["oplog"]["wall"]
        if row["source"] == "hs":
            return (row["hs"]["start_ts"] or {}).get("iso")
        tw = row.get("tw") or {}
        if "start_ts" in tw:
            return (wt_ts(tw["start_ts"]) or {}).get("iso")
        return None

    def scan_problems(self, ns: str) -> list[dict]:
        self.rows(ns)
        return self._rows.get("__stats__" + ns, {}).get("problems", [])

    def row(self, ns: str, rid: str) -> dict:
        for r in self.rows(ns):
            if r["rid"] == rid:
                return r
        raise KeyError(f"행 없음: {rid}")

    def fields(self, ns: str, rows: list[dict] | None = None) -> list[dict]:
        """최상위 필드와 타입. 모든 행(모든 출처)을 본다 - oplog, 끊긴 블록에만 있는 필드도 열이 된다."""
        cnt = collections.OrderedDict()
        types = collections.defaultdict(collections.Counter)
        for r in (self.rows(ns) if rows is None else rows):
            d = r.get("doc")
            if not isinstance(d, dict):
                continue
            for k, v in d.items():
                cnt[k] = cnt.get(k, 0) + 1
                types[k][type_name(v)] += 1
        order = sorted(cnt, key=lambda k: (k != "_id", -cnt[k]))
        return [{"name": k, "count": cnt[k], "types": dict(types[k])} for k in order]

    def stats(self, ns: str) -> dict:
        rs = self.rows(ns)
        c = self.catalog[ns]
        s = self.sizes.get(f"table:{c['ident']}") or {}
        live = sum(1 for r in rs if r["source"] == "file" and r["state"] == "live")
        return {"rows": len(rs), "by_state": dict(collections.Counter(r["state"] for r in rs)),
                "by_source": dict(collections.Counter(r["source"] for r in rs)),
                "chains": len({r["chain"]["id"] for r in rs if r.get("chain")}),
                "problems": sum(1 for r in rs if r.get("problem")),
                "size_storer": s.get("numRecords"), "live_file_rows": live,
                "count_match": None if s.get("numRecords") is None else int(s["numRecords"]) == live,
                "scan_problems": len(self.scan_problems(ns))}

    def detail(self, ns: str, rid: str) -> dict:
        r = self.row(ns, rid)
        c = self.catalog[ns]
        out = {k: r.get(k) for k in ("rid", "source", "state", "record_id", "block", "cell_off", "value_off",
                                       "problem", "note", "also_in", "created", "deleted_at", "oid_time", "chain",
                                       "oplog", "hs")}
        out["file"] = f"{c['ident']}.wt" if r["source"] in ("file", "stale") else ("WiredTigerHS.wt" if r["source"] == "hs" else
                                                                                    f"{self.catalog.get('local.oplog.rs', {}).get('ident')}.wt (oplog)")
        tw = r.get("tw") or {}
        out["time_window"] = {k: (wt_ts(v) if k.endswith("_ts") else v) for k, v in tw.items()}
        if r.get("block") is not None and r["source"] in ("file", "stale", "hs"):
            wf = self.table(c["ident"]) if r["source"] != "hs" else self.table("WiredTigerHS")
            try:
                h, _ = wf.block(r["block"])
                out["page"] = {k: h[k] for k in ("type_name", "flag_names", "write_gen", "mem_size", "entries", "disk_size",
                                                   "checksum", "block_flags", "version")}
                out["page"]["checksum_ok"] = WTFile.checksum_ok(wf.data[r["block"]:r["block"] + h["disk_size"]], h)
                out["page"]["compressed"] = bool(h["flags"] & 1)
                out["page"]["compressor"] = wf.compressor
            except Exception as e:
                out["page"] = {"error": str(e)}
        doc = r.get("doc")
        out["json"] = bsonlib.to_json(doc, 4096) if doc is not None else None
        raw = r.get("raw")
        if raw is not None:
            out["raw_len"] = len(raw)
            out["raw_sha256"] = hashlib.sha256(raw).hexdigest()
            out["hex"] = raw[:65536].hex()
            out["hex_truncated"] = len(raw) > 65536
            try:
                out["elements"] = bsonlib.elements(raw)
            except Exception:
                out["elements"] = []
        out["versions"] = []
        if r.get("chain"):
            for x in self.rows(ns):
                if x.get("chain") and x["chain"]["id"] == r["chain"]["id"]:
                    out["versions"].append({"rid": x["rid"], "source": x["source"], "state": x["state"], "vtime": x["vtime"],
                                            "pos": x["chain"]["pos"], "json": bsonlib.to_json(x["doc"], 64) if x["doc"] is not None else None,
                                            # 필드별 전체 값 해시 - 앞부분만 같은 바이너리도 다르게 잡는다
                                            "fh": {f: hashlib.sha1(canonical(v).encode()).hexdigest()[:16] for f, v in x["doc"].items()}
                                            if isinstance(x["doc"], dict) else {}})
            out["versions"].sort(key=lambda v: v["pos"])
        # 이 문서의 oplog 이벤트
        if isinstance(doc, dict) and "_id" in doc:
            key = canonical(doc["_id"])
            evs = []
            for e in self.oplog_events():
                if e["ns"] == ns and e["op"] in ("i", "u", "d"):
                    from .oplog import target_id
                    t = target_id(e)
                    if t is not None and canonical(t) == key:
                        evs.append(event_view(e))
            out["oplog_events"] = evs
        return out

    def collection_oplog(self, ns: str) -> list[dict]:
        return [event_view(e) for e in self.oplog_events() if e["ns"] == ns]

    # ------------------------------------------------------------------ GridFS
    def _gridfs_build(self, bucket: str, only: str | None = None) -> list[dict]:
        """files/chunks 를 모든 출처에서 모아 파일 단위로 조립. only 를 주면 그 파일만 (내려받기용)."""
        fns, cns = bucket + ".files", bucket + ".chunks"
        if fns not in self.catalog or cns not in self.catalog:
            raise KeyError(f"GridFS 버킷 없음: {bucket}")
        meta = {}
        if bucket in self.catalog:                         # 같은 이름의 메타 컬렉션 (예: Rocket.Chat uploads)
            for r in self.rows(bucket):
                d = r.get("doc")
                if isinstance(d, dict) and "_id" in d:
                    k = canonical(d["_id"])
                    if k not in meta or r["state"] == "live":
                        meta[k] = d
        files = {}
        for r in self.rows(fns):
            d = r.get("doc")
            if isinstance(d, dict) and "_id" in d:
                k = canonical(d["_id"])
                if only is not None and k != only:
                    continue
                if k not in files or SOURCE_ORDER[r["source"]] < SOURCE_ORDER[files[k]["row"]["source"]]:
                    files[k] = {"row": r, "doc": d}
        chunks = collections.defaultdict(dict)
        bad = collections.Counter()
        for r in self.rows(cns):
            d = r.get("doc")
            if not isinstance(d, dict) or not isinstance(d.get("data"), Binary):
                continue
            k = canonical(d.get("files_id"))
            if only is not None and k != only:
                continue
            n = d.get("n")
            if isinstance(n, bool) or not isinstance(n, int):
                bad[k] += 1                                # 순번이 정수가 아닌 청크는 조립에 쓰지 않는다
                continue
            prev = chunks[k].get(n)
            if prev is None or SOURCE_ORDER[r["source"]] < SOURCE_ORDER[prev[0]]:
                chunks[k][n] = (r["source"], d["data"].data, r["state"])
            files.setdefault(k, None)
        out = []
        for k, f in files.items():
            parts = chunks.get(k, {})
            doc = f["doc"] if f else None
            length = doc.get("length") if doc else None
            order = sorted(parts)
            contiguous = order == list(range(len(order)))
            data = b"".join(parts[i][1] for i in order)
            srcs = collections.Counter(p[0] for p in parts.values())
            m = meta.get(k) or {}
            up = (doc or {}).get("uploadDate")
            out.append({"key": k, "id": bsonlib.to_json(doc["_id"]) if doc else json.loads(k),
                        "filename": (doc or {}).get("filename"), "name": m.get("name"),
                        "type": m.get("type") or (doc or {}).get("contentType"),
                        "length": length, "chunk_size": (doc or {}).get("chunkSize"),
                        "upload_date": up.iso() if isinstance(up, Date) else None,
                        "files_source": f["row"]["source"] if f else None, "files_state": f["row"]["state"] if f else "missing",
                        "chunks": len(parts), "chunk_sources": dict(srcs), "mixed_sources": len(srcs) > 1,
                        "bad_chunks": bad.get(k, 0), "contiguous": contiguous, "bytes": len(data),
                        "complete": bool(parts) and contiguous and isinstance(length, int) and len(data) == length,
                        "sha256": hashlib.sha256(data).hexdigest() if data else None, "magic": magic(data),
                        "_data": data})
        out.sort(key=lambda x: (x["upload_date"] or "", x["key"]))
        return out

    def gridfs(self, bucket: str) -> list[dict]:
        """bucket = '<db>.<prefix>' (예: rocketchat.rocketchat_uploads).
        complete = 청크 번호가 0부터 빠짐없고, 조립 길이 = files.length. mixed_sources = 청크 출처가 섞임 (서로 다른 버전일 수 있음)."""
        return [{k: v for k, v in f.items() if k != "_data"} for f in self._gridfs_build(bucket)]

    def gridfs_data(self, bucket: str, key: str) -> tuple[bytes, dict]:
        for f in self._gridfs_build(bucket, only=key):
            if f["key"] == key:
                return f.pop("_data"), f
        raise KeyError("파일 없음")

    def field_binary(self, ns: str, rid: str, field: str) -> bytes:
        d = self.row(ns, rid).get("doc") or {}
        v = d.get(field)
        if not isinstance(v, Binary):
            raise KeyError(f"바이너리 필드가 아님: {field}")
        return v.data

    # ------------------------------------------------------------------ 정보, 검증
    def info(self) -> dict:
        files = self.source.files()
        kinds = collections.Counter()
        total = 0
        for n, sz in files:
            total += sz
            kinds["collection" if n.startswith("collection-") else "index" if n.startswith("index-") else
                  "journal" if n.startswith("journal/") else "diagnostic" if n.startswith("diagnostic.data/") else "other"] += 1
        storage = None
        if self.source.exists("storage.bson"):
            try:
                storage = bsonlib.to_json(bsonlib.decode(self.source.read("storage.bson")))
            except Exception as e:
                storage = {"error": str(e)}
        cks = checkpoints(self.turtle["file:WiredTiger.wt"])
        wt = self._tables["WiredTiger"]
        compressors = collections.Counter(cfg_value(v, "block_compressor") or "(none)" for k, v in self.metadata.items()
                                          if k.startswith("file:"))
        return {"input": str(self.source.input_path), "input_kind": self.source.kind, "dbpath": self.source.dbpath,
                "wiredtiger_version": self.turtle.get("WiredTiger version string"),
                "storage_bson": storage, "files": len(files), "bytes": total, "file_kinds": dict(kinds),
                "journal": [{"name": n, "size": sz} for n, sz in files if n.startswith("journal/")],
                "mongod_lock_size": self.source.size("mongod.lock") if self.source.exists("mongod.lock") else None,
                "metadata_checkpoint": {**(cks[-1] if cks else {}), "time_iso": ts_iso(cks[-1]["time"]) if cks else None,
                                        "file_size": (self.meta_ckpt or {}).get("file_size"), "actual_size": len(wt.data)},
                "metadata_keys": len(self.metadata), "compressors": dict(compressors),
                "collections": len(self.catalog), "databases": len(self.databases())}

    def validate(self, deep: bool = False) -> list[dict]:
        """자체 검증. deep 이면 모든 컬렉션의 행을 읽어 sizeStorer 와 비교한다."""
        out = []
        wt = self._tables["WiredTiger"]
        fs = (self.meta_ckpt or {}).get("file_size")
        out.append({"check": "WiredTiger.wt 체크포인트 file_size = 실제 크기", "ok": fs == len(wt.data),
                    "detail": f"{fs} / {len(wt.data)}"})
        raw = wt.data[self.meta_ckpt["root"][0]:self.meta_ckpt["root"][0] + self.meta_ckpt["root"][1]] if self.meta_ckpt and self.meta_ckpt["root"] else b""
        if raw:
            from .wtfile import page_header
            out.append({"check": "메타데이터 루트 블록 CRC-32C", "ok": WTFile.checksum_ok(raw, page_header(raw)), "detail": ""})
        out.append({"check": "_mdb_catalog 컬렉션 수", "ok": len(self.catalog) > 0, "detail": str(len(self.catalog))})
        cp = getattr(self, "catalog_problems", [])
        out.append({"check": "카탈로그 항목 해석", "ok": True if not cp else None, "detail": "; ".join(cp[:10]) or "문제 없음"})
        self.oplog_events()
        self.history_store()
        op = getattr(self, "oplog_problems", 0)
        hp = getattr(self, "hs_problems", [])
        out.append({"check": "oplog 항목 해석", "ok": True if not op else None, "detail": f"해석 실패 {op}건"})
        out.append({"check": "히스토리 스토어 항목 해석", "ok": True if not hp else None, "detail": "; ".join(hp[:5]) or "문제 없음"})
        if deep:
            errs, diff = [], []
            for ns in sorted(self.catalog):
                try:
                    st = self.stats(ns)
                except Exception as e:
                    errs.append(f"{ns}: {type(e).__name__}: {e}")
                    continue
                if st["count_match"] is False:
                    diff.append(f"{ns}: sizeStorer {st['size_storer']} / 현재 파일 {st['live_file_rows']}")
            out.append({"check": "모든 컬렉션 해석", "ok": not errs, "detail": "; ".join(errs[:20]) or f"{len(self.catalog)}개 오류 없음"})
            # sizeStorer 는 주기적으로만 기록되므로 자주 쓰는 컬렉션(oplog 등)은 늦을 수 있다 → 경고(ok=None)
            out.append({"check": "sizeStorer 문서 수 = 현재 파일 live 행", "ok": True if not diff else None,
                        "detail": ("; ".join(diff[:20]) + " - sizeStorer 는 주기적으로만 기록되어 늦을 수 있다") if diff
                        else f"{len(self.catalog)}개 일치"})
        return out

    def close(self):
        self.source.close()


def iso_epoch(s) -> float:
    if not s:
        return 0.0
    try:
        return _dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def type_name(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "double"
    if isinstance(v, str):
        return "string"
    if isinstance(v, dict):
        return "object"
    if isinstance(v, list):
        return "array"
    if isinstance(v, ObjectId):
        return "objectId"
    if isinstance(v, Date):
        return "date"
    if isinstance(v, Binary):
        return "binData"
    if isinstance(v, Timestamp):
        return "timestamp"
    return getattr(v, "kind", "other")


def event_view(e: dict) -> dict:
    from .oplog import target_id
    o = e.get("o")
    t = target_id(e)
    if e["op"] == "u" and isinstance(o, dict):
        diff = o.get("diff") if o.get("$v") == 2 else o
        summary = "diff " + ",".join(sorted((diff or {}).keys())) if isinstance(diff, dict) else ""
    elif e["op"] == "i" and isinstance(o, dict):
        summary = f"문서 필드 {len(o)}개"
    elif e["op"] == "c" and isinstance(o, dict):
        summary = "명령 " + ",".join(list(o.keys())[:3])
    else:
        summary = ""
    return {"recordId": e["recordId"], "sub": e["sub"], "ts": {"t": e["ts"][0], "i": e["ts"][1]} if e["ts"] else None,
            "wall": ms_iso(e["wall"]), "op": e["op"], "ns": e["ns"], "id": bsonlib.to_json(t, 32) if t is not None else None, "idk": canonical(t) if t is not None else None,
            "summary": summary, "txn": e.get("txn"), "o": bsonlib.to_json(o, 64), "o2": bsonlib.to_json(e.get("o2"), 64)}


def magic(b: bytes) -> str:
    for sig, name in ((b"%PDF-", "pdf"), (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"),
                      (b"PK\x03\x04", "zip"), (b"RIFF", "riff"), (b"\x1f\x8b", "gzip"), (b"OggS", "ogg"),
                      (b"ID3", "mp3"), (b"\x00\x00\x00", "mp4?")):
        if b.startswith(sig):
            return name
    return ""


def open_dbpath(path) -> DbPath:
    src = open_source(path)
    try:
        return DbPath(src)
    except Exception:
        src.close()
        raise

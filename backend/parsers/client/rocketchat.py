from __future__ import annotations

import base64
import json
import re
import sqlite3
from datetime import date, datetime
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

from ...artifacts import chromium_cache, rc_e2e
from ..base import CERTAIN, BaseParser, error_section, finding, fmt_dt, fmt_ms, fmt_webkit, kv, short, table

import backend.vendor
from ccl_chromium_reader import ccl_chromium_cache, ccl_chromium_indexeddb, ccl_chromium_localstorage

ROOM_TYPE = {"c": "공개 채널", "p": "비공개 그룹", "d": "DM", "l": "옴니채널"}
LS_MEANING = {
    "Meteor.loginToken": "로그인 토큰 (서버 users.services.resume.loginTokens 의 hashedToken = base64(SHA-256(토큰)))",
    "Meteor.loginTokenExpires": "로그인 토큰 만료 시각 (로컬 표기)",
    "Meteor.userId": "로그인 사용자 _id",
    "private_key": "E2E 개인키 (RSA JWK, 평문)",
    "public_key": "E2E 공개키 (RSA JWK)",
    "e2e.randomPassword": "E2E 복구 비밀번호 (서버 users.e2e.private_key 를 푸는 비밀번호)",
    "userLanguage": "UI 언어",
}


def plain(v):
    if isinstance(v, datetime):
        return fmt_dt(v)
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, dict):
        return {str(k): plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [plain(x) for x in v]
    if isinstance(v, (bytes, bytearray)):
        return f"<{len(v)} B>"
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return str(v)


def tstr(v) -> str:
    if isinstance(v, datetime):
        return fmt_dt(v)
    if isinstance(v, str) and re.match(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d", v):
        try:
            return fmt_dt(datetime.fromisoformat(v.strip().replace("Z", "+00:00")))
        except ValueError:
            return v.replace("T", " ").rstrip("Z")[:23]
    if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0:
        return fmt_ms(v if v > 1e11 else v * 1000)
    if isinstance(v, dict) and "$date" in v:
        return fmt_ms(v["$date"])
    return ""


def clean(v):
    if isinstance(v, str):
        try:
            v.encode("utf-8")
            return v
        except UnicodeEncodeError:
            return v.encode("utf-8", "surrogatepass").decode("utf-8", "replace")
    if isinstance(v, dict):
        return {clean(k): clean(x) for k, x in v.items()}
    if isinstance(v, list):
        return [clean(x) for x in v]
    return v


def jdump(v, n=None) -> str:
    s = json.dumps(plain(v), ensure_ascii=False)
    return s if n is None or len(s) <= n else s[:n] + "…"


def find_app_dir(root: Path) -> Path:
    for d in sorted((p for p in root.rglob("Partitions") if p.is_dir()), key=lambda p: len(p.parts)):
        if any(x.name.lower().startswith("http") for x in d.iterdir()):
            return d.parent
    for f in sorted(root.rglob("config.json"), key=lambda p: len(p.parts)):
        if (f.parent / "logs").is_dir() or f.parent.name.lower().startswith("rocket"):
            return f.parent
    return root


def find_partitions(app: Path) -> list[tuple[str, Path]]:
    out = []
    d = app / "Partitions"
    if not d.is_dir():
        return out
    for p in sorted(d.iterdir()):
        if not p.is_dir():
            continue
        if p.name.lower().startswith("http") and not (p / "IndexedDB").exists() and not (p / "Local Storage").exists():
            scheme = unquote(p.name).rstrip(":")
            for h in sorted(p.iterdir()):
                if h.is_dir():
                    out.append((f"{scheme}://{unquote(h.name)}", h))
        else:
            out.append((unquote(p.name), p))
    return out


class RocketChatClientParser(BaseParser):
    mode = "client"
    app = "rocketchat"
    is_dummy = False

    def parse(self, root: Path, inventory: list[dict]) -> dict:
        app = find_app_dir(root)
        parts = find_partitions(app)
        sections: list[dict] = []
        ctx: dict = {"counts": {}, "keys": {}, "privs": [], "msgs": [], "drafts": []}

        steps = [
            (self.config, "앱 설정 (config.json)"),
            (self.local_storage, "Local Storage"),
            (self.indexeddb, "IndexedDB (localforage)"),
            (self.e2e, "E2E 키, 복호화"),
            (self.cookies, "쿠키"),
            (self.cache, "캐시"),
            (self.logs, "앱 로그"),
            (self.chromium, "Chromium 공통 설정"),
        ]
        for fn, title in steps:
            try:
                out = fn(app, parts, ctx)
                sections.extend(out if isinstance(out, list) else [out])
            except Exception as e:
                sections.append(error_section(fn.__name__, title, e))

        order = ["messages", "e2e_keys", "drafts", "servers", "idb_rooms", "idb_subscriptions", "localstorage", "idb_versions",
                 "idb_settings", "trusted_certs", "downloads", "app_config", "cookies", "cache_entries", "app_log", "errors_log", "chromium"]
        sections.sort(key=lambda x: order.index(x["id"]) if x["id"] in order else len(order))
        c = ctx["counts"]
        summary = [
            {"label": "등록 서버", "value": c.get("servers", 0)},
            {"label": "서버 버전", "value": c.get("server_version") or "-"},
            {"label": "앱 버전", "value": c.get("app_version") or "-"},
            {"label": "방 (캐시)", "value": c.get("rooms", 0)},
            {"label": "메시지 이력 (lastMessage)", "value": c.get("messages", 0)},
            {"label": "E2E 복호화", "value": f"{c.get('decrypted', 0)} / {c.get('encrypted', 0)}"},
            {"label": "입력창 초안", "value": c.get("drafts", 0)},
        ]
        return clean({"summary": summary, "sections": sections})


    SERVER_COLS = [("file", "판"), ("title", "이름"), ("url", "서버 URL"), ("version", "서버 버전"), ("logged_in", "로그인"), ("roles", "역할"),
                   ("last_path", "마지막 화면 (lastPath)"), ("page_title", "페이지 제목"), ("presence", "상태"),
                   ("validated", "지원 버전 확인 (UTC)"), ("source", "확인 출처"), ("window_title", "창 제목"), ("badge", "안 읽음"),
                   ("favicon", "아이콘")]

    @staticmethod
    def _config_files(app: Path) -> list[Path]:
        out = [app / "config.json"] if (app / "config.json").is_file() else []
        out += sorted(p for p in app.glob("config.json?*") if p.is_file() and p.name != "config.json")
        return out

    @staticmethod
    def _server_row(fname: str, cfg: dict, s: dict) -> dict:
        fav = s.get("favicon") or ""
        sv = s.get("supportedVersions")
        src = s.get("supportedVersionsSource") or (sv.get("source") if isinstance(sv, dict) else "") or ""
        return {"file": fname, "title": s.get("title", ""), "url": s.get("url", ""), "version": s.get("version", ""),
                "logged_in": str(s.get("userLoggedIn", "")), "roles": ", ".join(map(str, s.get("userRoles") or [])),
                "last_path": s.get("lastPath", ""), "page_title": s.get("pageTitle", ""), "presence": s.get("presence", ""),
                "validated": tstr(s.get("supportedVersionsValidatedAt")), "source": str(src),
                "window_title": str(cfg.get("mainWindowTitle", "")), "badge": str(s.get("badge", "")),
                "favicon": (fav[:30] + f"… ({len(fav)}자)") if isinstance(fav, str) and len(fav) > 30 else str(fav)}

    def config(self, app: Path, parts, ctx) -> list[dict]:
        files = self._config_files(app)
        if not files:
            return [table("servers", "등록 서버", self.SERVER_COLS, [],
                          "config.json 이 없습니다. 문서 사례처럼 사용 중 레코드가 없으면 디스크 이미지의 삭제된 MFT 레코드, $LogFile 에서 "
                          "이전 판을 찾아 config.json(또는 config.json.copy0, copy1 …) 이름으로 함께 넣어 주세요.")]
        cfgs, bad = [], []
        for f in files:
            try:
                c = json.loads(f.read_text(encoding="utf-8", errors="replace"))
                if not isinstance(c, dict):
                    raise ValueError("JSON 객체가 아님")
                cfgs.append((f.name, c))
            except Exception as e:
                bad.append(f"{f.name} ({type(e).__name__})")
        if not cfgs:
            return [table("servers", "등록 서버", self.SERVER_COLS, [], "config.json 판을 하나도 해석하지 못했습니다: " + ", ".join(bad))]
        main_name, cfg = cfgs[0]
        rows = []
        for fname, c in cfgs:
            for s in c.get("servers") or []:
                if isinstance(s, dict):
                    rows.append(self._server_row(fname, c, s))
        ctx["counts"]["servers"] = len({r["url"] for r in rows if r["file"] == main_name})
        main_rows = [r for r in rows if r["file"] == main_name]
        if main_rows:
            ctx["counts"]["server_version"] = main_rows[0]["version"]
        desc = ("config.json 의 servers. 앱에 추가한 서버, 로그인 여부, 마지막으로 본 화면(lastPath, 예: /group/Trip, /direct/<rid>)이 남습니다. "
                "함께 넣은 이전 판(config.json.copy* 등)은 '판' 열로 구분해 같이 보여 줍니다 (판마다 lastPath, 상태, 지원 버전 확인 시각을 비교).")
        if bad:
            desc += " 해석하지 못한 판: " + ", ".join(bad) + "."
        out = [table("servers", "등록 서버", self.SERVER_COLS, rows, desc)]
        certs, seen = [], {}
        for fname, c in cfgs:
            tc = c.get("trustedCertificates")
            for host, pem in (tc.items() if isinstance(tc, dict) else []):
                try:
                    info = self._cert_info(pem)
                except Exception as e:
                    info = {"subject": f"(해석 실패: {type(e).__name__})", "length": len(str(pem)), "sha256": ""}
                k = (host, info.get("sha256") or str(pem)[:80])
                if k in seen:
                    seen[k]["file"] += ", " + fname
                    continue
                seen[k] = row = {"file": fname, "host": host, **info}
                certs.append(row)
        out.append(table("trusted_certs", "사용자가 신뢰한 서버 인증서", [("file", "판"), ("host", "호스트"), ("subject", "주체 (CN)"),
                                                               ("issuer", "발급자 (CN)"), ("sha256", "SHA-256 (DER)"), ("length", "PEM 길이")], certs,
                         "config.json 의 trustedCertificates. 인증서 오류 창에서 사용자가 '신뢰'를 누른 서버 인증서입니다 (사설 인증서 사용 서버). "
                         "판마다 인증서가 다르면 서버가 인증서를 다시 발급한 것입니다 (예: Caddy 중간 인증서 갱신)."))
        dl = cfg.get("downloads") or {}
        drows = []
        for k, d in (dl.items() if isinstance(dl, dict) else []):
            if isinstance(d, dict):
                drows.append({"id": k, "file": d.get("fileName", ""), "url": d.get("url", ""), "path": d.get("savePath", ""),
                              "size": d.get("totalBytes", ""), "state": d.get("state", ""), "server": d.get("serverTitle") or d.get("serverUrl", ""),
                              "start": fmt_ms(d.get("startedAt")), "end": fmt_ms(d.get("endedAt"))})
        out.append(table("downloads", "앱 다운로드 기록", [("start", "시작 (UTC)"), ("end", "완료 (UTC)"), ("file", "파일명"), ("url", "URL"),
                                                     ("path", "저장 경로"), ("size", "크기"), ("state", "상태"), ("server", "서버")], drows,
                         "config.json 의 downloads. 앱 안에서 받은 파일 (비어 있으면 {})."))
        items = {}
        for k, v in cfg.items():
            if k in ("servers", "trustedCertificates", "downloads"):
                continue
            items[k] = v if isinstance(v, str) else jdump(v, 2000)
        mig = (cfg.get("__internal__") or {}).get("migrations") if isinstance(cfg.get("__internal__"), dict) else None
        if isinstance(mig, dict) and mig.get("version"):
            ctx["counts"]["app_version"] = mig["version"]
        out.append(kv("app_config", "앱 설정 (기타)", items,
                      f"{main_name} 의 나머지 키 (이전 판의 차이는 '등록 서버' 표). mainWindowTitle = 마지막 창 제목, __internal__.migrations.version = 설정 형식(앱) 버전, "
                      "currentView / currentServerUrl = 마지막으로 본 서버."))
        return out

    @staticmethod
    def _cert_info(pem) -> dict:
        if not isinstance(pem, str):
            return {"subject": "", "issuer": "", "sha256": "", "length": ""}
        import hashlib
        m = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", pem, re.S)
        der = base64.b64decode(re.sub(r"\s", "", m[1])) if m else b""
        cns = []
        for x in re.finditer(rb"\x06\x03\x55\x04\x03[\x0c\x13\x14\x16\x1e]", der):
            i = x.end()
            if i < len(der) and der[i] < 0x80:
                cns.append(der[i + 1:i + 1 + der[i]].decode("utf-8", "replace"))
        two = len(cns) == 2
        return {"issuer": cns[0] if two else "", "subject": cns[1] if two else ", ".join(cns),
                "sha256": hashlib.sha256(der).hexdigest() if der else "", "length": len(pem)}


    def local_storage(self, app: Path, parts, ctx) -> list[dict]:
        cols = [("server", "서버"), ("seq", "seq"), ("state", "상태"), ("time", "기록 시각 (UTC)"), ("key", "키"), ("meaning", "의미"),
                ("value", "값"), ("origin", "origin")]
        d_cols = [("server", "서버"), ("state", "상태"), ("room", "방 rid"), ("thread", "스레드 tmid"), ("text", "초안"), ("time", "기록 시각 (UTC)"),
                  ("seq", "seq")]
        rows, drafts = [], []
        dirs = [(srv, p / "Local Storage" / "leveldb") for srv, p in parts] + [("(앱 루트)", app / "Local Storage" / "leveldb")]
        for srv, d in dirs:
            if not d.is_dir():
                continue
            try:
                self._ls_dir(srv, d, rows, drafts, ctx)
            except Exception as e:
                rows.append({"server": srv, "key": f"(Local Storage 읽기 실패: {type(e).__name__}: {e})", "state": "unknown"})
        ctx["drafts"] = drafts
        ctx["counts"]["drafts"] = sum(1 for x in drafts if not x["_rc"])
        return [
            table("drafts", "입력창 초안 (messagebox_)", d_cols, drafts,
                  "Local Storage 의 messagebox_<rid>[-<tmid>]. 입력하다 보내지 않은 글이 남고, 보내거나 지운 초안도 LevelDB 에 이전 값으로 남을 수 있습니다. "
                  "방 이름은 'IndexedDB 방' 표의 rid 로 확인합니다.", row_class="_rc"),
            table("localstorage", "Local Storage", cols, rows,
                  "Partitions\\https%3A\\<호스트>\\Local Storage\\leveldb. 로그인 토큰, 사용자 ID, E2E 개인키/공개키(JWK), E2E 복구 비밀번호가 평문으로 남습니다. "
                  "같은 키의 이전 값과 삭제 기록(사용자가 지운 복구 비밀번호 등)도 seq 순으로 보입니다.", row_class="state"),
        ]

    @staticmethod
    def _ls_dir(srv: str, d: Path, rows: list, drafts: list, ctx: dict) -> None:
        db = ccl_chromium_localstorage.LocalStoreDb(d)
        try:
            recs = sorted(db.iter_all_records(include_deletions=True), key=lambda r: r.leveldb_seq_number)
            latest: dict = {}
            for r in recs:
                latest[(r.storage_key, r.script_key)] = r.leveldb_seq_number
            for r in recs:
                batch = db.find_batch(r.leveldb_seq_number)
                t = fmt_dt(batch.timestamp) if batch and batch.timestamp else ""
                key = r.script_key or ""
                cur = latest.get((r.storage_key, key)) == r.leveldb_seq_number
                state = ("live" if r.is_live else "deleted") if cur else ("deleted" if not r.is_live else "updated")
                val = r.value if isinstance(r.value, str) else ("" if r.value is None else str(r.value))
                rows.append({"server": srv, "seq": r.leveldb_seq_number, "state": state, "time": t, "key": key,
                             "meaning": LS_MEANING.get(key, "입력창 초안 (방 rid[-스레드 tmid])" if key.startswith("messagebox_") else ""),
                             "value": val, "origin": r.storage_key})
                if key == "private_key" and val:
                    ctx["privs"].append((srv, cur and r.is_live, val))
                if key.startswith("messagebox_") and val:
                    rid, _, tmid = key[len("messagebox_"):].partition("-")
                    drafts.append({"server": srv, "state": "현재 값" if cur and r.is_live else "이전 값, 삭제됨",
                                   "_rc": "" if cur and r.is_live else "deleted", "room": rid, "thread": tmid, "text": val,
                                   "time": t, "seq": r.leveldb_seq_number})
        finally:
            db.close()


    def indexeddb(self, app: Path, parts, ctx) -> list[dict]:
        r_cols = [("server", "서버"), ("rid", "rid"), ("type", "유형"), ("name", "이름"), ("members", "참여자 (DM)"), ("msgs", "메시지 수"),
                  ("users", "인원"), ("created", "생성 (UTC)"), ("lm", "마지막 메시지 (UTC)"), ("encrypted", "E2E"), ("kid", "E2E 키 ID"),
                  ("topic", "주제"), ("updated", "_updatedAt (UTC)")]
        s_cols = [("server", "서버"), ("name", "방"), ("type", "유형"), ("user", "사용자"), ("joined", "참여 (UTC)"), ("ls", "마지막으로 읽음 (UTC)"),
                  ("unread", "안 읽음"), ("alert", "알림"), ("e2e", "E2EKey"), ("rid", "rid")]
        v_cols = [("server", "서버"), ("key", "키"), ("seq", "seq"), ("state", "판"), ("updated", "updatedAt (UTC)"), ("count", "레코드 수"),
                  ("version", "version"), ("token", "token (로그인 토큰)")]
        rooms, subs, versions, settings = [], [], [], []
        hist: dict = {}
        latest: dict = {}
        for srv, p in parts:
            idb_root = p / "IndexedDB"
            for d in sorted(idb_root.glob("*.indexeddb.leveldb")) if idb_root.is_dir() else []:
                try:
                    self._lf_scan(d, srv, hist, latest, versions)
                except Exception as e:
                    versions.append({"server": srv, "key": f"(IndexedDB 읽기 실패: {type(e).__name__}: {e})", "_gk": None})
        for v in versions:
            gk = v.pop("_gk", None)
            if gk is None:
                continue
            seq, _, live = latest[gk]
            cur = v["seq"] == seq
            v["state"] = ("최신 판" if live else "최신 기록 = 삭제") if cur else "이전 판"
            v["_rc"] = "" if cur and live else ("deleted" if cur else "updated")
        for h in hist.values():
            h["current"] = any(seq == latest[gk][0] and latest[gk][2] for gk, seq in h.pop("seen"))
        for (srv, _, _, key), (_, val, live) in sorted(latest.items(), key=lambda x: (x[0][0], x[0][1], x[0][2], x[0][3])):
            recs = val.get("records") if isinstance(val, dict) else None
            if not live or not isinstance(recs, list):
                continue
            for rec in recs:
                if not isinstance(rec, dict):
                    continue
                try:
                    if key == "rooms":
                        rooms.append(self._room_row(srv, rec))
                    elif key == "subscriptions":
                        subs.append(self._sub_row(srv, rec))
                        if rec.get("E2EKey"):
                            ctx["keys"].setdefault(srv, []).append((rec.get("fname") or rec.get("name") or rec.get("rid"), rec))
                    elif key == "public-settings":
                        settings.append({"server": srv, "id": str(rec.get("_id", "")), "value": rec.get("value")
                                         if isinstance(rec.get("value"), str) else jdump(rec.get("value"), 1000)})
                except Exception as e:
                    (rooms if key == "rooms" else subs if key == "subscriptions" else settings).append(
                        {"server": srv, "name": f"(레코드 해석 실패: {type(e).__name__})"})
        ctx["room_names"] = {(r.get("server"), r.get("rid")): r.get("name") or r.get("members") for r in rooms}
        ctx["msgs"] = list(hist.values())
        ctx["counts"]["rooms"] = len(rooms)
        return [
            table("idb_rooms", "방 (IndexedDB rooms, 최신 판)", r_cols, rooms,
                  "localforage 의 rooms 키 (서버 웹 앱의 방 캐시). 메시지 본문은 캐시하지 않고 방마다 lastMessage 만 있습니다."),
            table("idb_subscriptions", "구독 (IndexedDB subscriptions, 최신 판)", s_cols, subs,
                  "로그인 사용자가 참여한 방. ls = 마지막으로 읽은 시각, E2EKey = 사용자 공개키로 암호화한 방 키 (Local Storage 개인키로 복호화)."),
            table("idb_versions", "localforage 저장 판 (이전 값 포함)", v_cols, versions,
                  "keyvaluepairs 의 키별 저장 기록. 방, 구독이 바뀔 때마다 전체가 다시 저장되어 이전 판이 LevelDB 에 남습니다 "
                  "(주황 = 이전 판). token 은 Meteor 로그인 토큰입니다.", row_class="_rc"),
            table("idb_settings", "서버 공개 설정 (public-settings)", [("server", "서버"), ("id", "설정"), ("value", "값")], settings,
                  "서버 이름, E2E 사용 여부(E2E_Enable), 메시지 삭제 허용 여부 등 로그인 화면에 필요한 서버 설정의 캐시."),
        ]

    def _lf_scan(self, d: Path, srv: str, hist: dict, latest: dict, versions: list) -> None:
        idb = ccl_chromium_indexeddb.WrappedIndexDB(d)
        try:
            for dbid in idb.database_ids:
                db = idb[dbid.dbid_no]
                for sname in db.object_store_names:
                    if sname != "keyvaluepairs":
                        continue
                    store = db.get_object_store_by_name(sname)
                    for rec in store.iterate_records(bad_deserializer_data_handler=lambda k, v: None):
                        key = str(rec.key.value if hasattr(rec.key, "value") else rec.key)
                        gk = (srv, str(d), dbid.dbid_no, key)
                        seq, val = rec.ldb_seq_no, rec.value
                        recs = val.get("records") if isinstance(val, dict) else None
                        versions.append({"server": srv, "key": key, "seq": seq, "_gk": gk,
                                         "updated": tstr(val.get("updatedAt")) if isinstance(val, dict) else "",
                                         "count": len(recs) if isinstance(recs, list) else "",
                                         "version": val.get("version", "") if isinstance(val, dict) else "",
                                         "token": str(val.get("token", "")) if isinstance(val, dict) else jdump(val, 300)})
                        if key in ("rooms", "subscriptions") and isinstance(recs, list):
                            for r in recs:
                                if isinstance(r, dict):
                                    self._collect_lm(hist, srv, key, gk, seq, r)
                        if gk not in latest or seq > latest[gk][0]:
                            latest[gk] = (seq, val, bool(rec.is_live))
        finally:
            idb.close()

    @staticmethod
    def _room_row(srv, d) -> dict:
        return {"server": srv, "rid": d.get("_id", ""), "type": f"{d.get('t', '')} ({ROOM_TYPE.get(d.get('t'), '')})",
                "name": d.get("fname") or d.get("name") or "", "members": ", ".join(map(str, d.get("usernames") or [])),
                "msgs": d.get("msgs", ""), "users": d.get("usersCount", ""), "created": tstr(d.get("ts")), "lm": tstr(d.get("lm")),
                "encrypted": "예" if d.get("encrypted") else "", "kid": d.get("e2eKeyId", ""), "topic": d.get("topic", ""),
                "updated": tstr(d.get("_updatedAt"))}

    @staticmethod
    def _sub_row(srv, d) -> dict:
        return {"server": srv, "name": d.get("fname") or d.get("name") or "", "type": d.get("t", ""),
                "user": (d.get("u") or {}).get("username", ""), "joined": tstr(d.get("ts")), "ls": tstr(d.get("ls")),
                "unread": d.get("unread", ""), "alert": str(d.get("alert", "")),
                "e2e": f"{len(str(d.get('E2EKey')))}자" if d.get("E2EKey") else "", "rid": d.get("rid", "")}

    @staticmethod
    def _collect_lm(hist, srv, key, gk, seq, rec):
        lm = rec.get("lastMessage")
        if not isinstance(lm, dict) or not lm.get("_id"):
            return
        sig = (srv, str(lm.get("_id")), tstr(lm.get("_updatedAt")), jdump(lm.get("msg", "")), jdump(lm.get("content")))
        rid = rec.get("rid") if key == "subscriptions" else rec.get("_id")
        h = hist.get(sig)
        if h is None:
            hist[sig] = h = {"server": srv, "id": str(lm.get("_id")), "rid": lm.get("rid") or rid, "lm": lm, "seqs": set(),
                             "from": set(), "seen": set(), "current": False}
        h["seqs"].add(seq)
        h["from"].add(key)
        h["seen"].add((gk, seq))


    def e2e(self, app: Path, parts, ctx) -> list[dict]:
        k_cols = [("server", "서버"), ("room", "방"), ("kid", "키 ID"), ("alg", "알고리즘"), ("key", "방 키 (base64url)"), ("kind", "구분"),
                  ("result", "결과")]
        m_cols = [("state", "판"), ("ts", "보낸 시각 (UTC)"), ("room", "방"), ("user", "보낸 사람"), ("type", "유형"), ("msg", "본문 (캐시 사본)"),
                  ("plain", "복호화 본문"), ("files", "첨부"), ("file_keys", "첨부 복호 키 (AES-256-CTR key / iv / sha256)"), ("edited", "편집 (UTC)"),
                  ("from", "출처 (키)"), ("seq", "LevelDB seq"), ("updated", "_updatedAt (UTC)"), ("server", "서버"), ("id", "_id")]
        key_rows = []
        keys: dict[str, dict[str, dict]] = {}
        note = ""
        if not rc_e2e.AVAILABLE:
            note = "pycryptodome 이 설치되어 있지 않아 복호화하지 않았습니다 (pip install -r requirements.txt)."
        room_keys: dict[tuple, dict] = {}
        servers = sorted({x[0] for x in ctx["privs"]} | set(ctx["keys"]))
        for srv in servers if rc_e2e.AVAILABLE else []:
            cand = sorted((x for x in ctx["privs"] if x[0] in (srv, "(앱 루트)")), key=lambda x: (x[0] != srv, not x[1]))
            privs, seen = [], set()
            for _, _, val in cand:
                if val in seen:
                    continue
                seen.add(val)
                try:
                    privs.append(rc_e2e.private_key(val))
                except Exception:
                    continue
            if not privs:
                if ctx["keys"].get(srv):
                    key_rows.append({"server": srv, "result": "이 서버의 private_key 가 없거나 RSA 키로 해석하지 못함"})
                continue
            for room, sub in ctx["keys"].get(srv, []):
                cands = [("현재 키", sub.get("E2EKey"))] + [("이전 키 (oldRoomKeys)", o.get("E2EKey")) for o in sub.get("oldRoomKeys") or []
                                                         if isinstance(o, dict) and o.get("E2EKey")]
                for kind, ek in cands:
                    err = None
                    for n, priv in enumerate(privs):
                        try:
                            kid, jwk = rc_e2e.room_key(priv, str(ek))
                        except Exception as e:
                            err = e
                            continue
                        if kid:
                            keys.setdefault(srv, {})[kid] = jwk
                        if kind == "현재 키":
                            room_keys[(srv, sub.get("rid"))] = jwk
                        key_rows.append({"server": srv, "room": room, "kid": kid, "alg": jwk.get("alg", ""), "key": jwk.get("k", ""),
                                         "kind": kind + (", 이전 개인키로" if n else ""), "result": "복호화 성공"})
                        break
                    else:
                        key_rows.append({"server": srv, "room": room, "kind": kind, "result": f"실패: {err}"})
        rows = []
        names = ctx.get("room_names", {})
        enc = dec = 0
        for h in ctx["msgs"]:
            try:
                row, e1, d1 = self._lm_row(h, keys, room_keys, names)
            except Exception as e:
                row, e1, d1 = {"state": "", "_rc": "", "id": h.get("id", ""), "server": h.get("server", ""),
                               "plain": f"(행 해석 실패: {type(e).__name__}: {e})", "ts": ""}, 0, 0
            rows.append(row)
            enc += e1
            dec += d1
        rows.sort(key=lambda r: (r["ts"] or "~", r["id"]))
        ctx["counts"].update(messages=len(rows), encrypted=enc, decrypted=dec)
        return self._e2e_tables(rows, key_rows, m_cols, k_cols, note)

    def _lm_row(self, h, keys, room_keys, names):
        enc = dec = 0
        lm = h["lm"]
        u = lm.get("u") if isinstance(lm.get("u"), dict) else {}
        t = str(lm.get("t") or "")
        content = lm.get("content") if isinstance(lm.get("content"), dict) else None
        plain_txt, file_keys = "", []
        if t == "e2e" or content:
            enc += 1
            ks = dict(keys.get(h["server"], {}))
            rk = room_keys.get((h["server"], h["rid"]))
            if rk:
                ks[""] = rk
            try:
                obj, alg, kid = rc_e2e.decrypt_content(ks, content, lm.get("msg") if not content else None)
                plain_txt, finfo = rc_e2e.plaintext_summary(obj)
                file_keys = [f"{f['title']}: key {f['key']} / iv {f['iv']} / sha256 {f['sha256']}" for f in finfo if f.get("key")]
                if not plain_txt and finfo:
                    plain_txt = "(첨부만)"
                dec += 1
            except Exception as e:
                plain_txt = f"(복호화 실패: {e})"
        files = []
        for f in lm.get("files") or ([lm["file"]] if isinstance(lm.get("file"), dict) else []):
            if isinstance(f, dict):
                files.append(f"{f.get('name', '')} ({f.get('type', '')}, {f.get('size', '')} B, id {f.get('_id', '')})")
        ed = lm.get("editedBy") if isinstance(lm.get("editedBy"), dict) else {}
        msg = lm.get("msg")
        msg = msg if isinstance(msg, str) else ("" if msg is None else jdump(msg, 2000))
        row = {
            "state": "최신 판" if h["current"] else "이전 판", "_rc": "" if h["current"] else "updated",
            "ts": tstr(lm.get("ts")), "room": names.get((h["server"], h["rid"])) or str(h["rid"] or ""),
            "user": str(u.get("username", "")), "type": t, "msg": "" if (t == "e2e" and not content and msg) else msg,
            "plain": plain_txt, "files": "\n".join(files), "file_keys": "\n".join(file_keys),
            "edited": (tstr(lm.get("editedAt")) + (f" by {ed.get('username', '')}" if ed else "")).strip(),
            "from": ", ".join(sorted(h["from"])), "seq": f"{min(h['seqs'])}~{max(h['seqs'])}" if len(h["seqs"]) > 1 else str(min(h["seqs"])),
            "updated": tstr(lm.get("_updatedAt")), "server": h["server"], "id": h["id"],
        }
        return row, enc, dec

    def _e2e_tables(self, rows, key_rows, m_cols, k_cols, note):
        desc = ("IndexedDB rooms, subscriptions 의 모든 판에서 모은 lastMessage 입니다. 메시지가 올 때마다 판이 새로 저장되어 이전 판의 lastMessage 가 "
                "메시지 이력이 됩니다 (서버에서 지운 메시지, 첨부도 남을 수 있음). E2E 메시지는 Local Storage 개인키 → 방 키로 복호화했습니다.")
        if note:
            desc += " " + note
        return [
            table("messages", "메시지 이력 (lastMessage, E2E 복호화)", m_cols, rows, desc, row_class="_rc"),
            table("e2e_keys", "E2E 방 키", k_cols, key_rows,
                  "Local Storage 의 private_key(RSA JWK)로 subscriptions 의 E2EKey(키 ID 36자 + base64)를 RSA-OAEP(SHA-256) 복호화한 방 키(AES-256-GCM)입니다. "
                  "이 키로 서버 DB 의 같은 방 암호문(rocketchat_message.content)도 풀 수 있습니다." + (" " + note if note else "")),
        ]


    def cookies(self, app: Path, parts, ctx) -> dict:
        cols = [("where", "위치"), ("host", "호스트"), ("name", "이름"), ("created", "생성 (UTC)"), ("expires", "만료 (UTC)"),
                ("last_access", "마지막 접근 (UTC)"), ("value", "평문 값"), ("encrypted", "암호문")]
        rows = []
        for where, f in [("(앱 루트)", app / "Network" / "Cookies")] + [(srv, p / "Network" / "Cookies") for srv, p in parts]:
            if not f.is_file():
                continue
            try:
                con = sqlite3.connect(f"file:{quote(f.as_posix())}?mode=ro&immutable=1", uri=True)
                try:
                    con.row_factory = sqlite3.Row
                    for r in con.execute("SELECT * FROM cookies ORDER BY creation_utc"):
                        r = dict(r)
                        e = r.get("encrypted_value") or b""
                        rows.append({"where": where, "host": r.get("host_key", ""), "name": r.get("name", ""),
                                     "created": fmt_webkit(r.get("creation_utc")), "expires": fmt_webkit(r.get("expires_utc")),
                                     "last_access": fmt_webkit(r.get("last_access_utc")), "value": r.get("value", ""),
                                     "encrypted": f"{len(e)} B (접두어 {e[:3].decode('latin1')!r})" if e else ""})
                finally:
                    con.close()
            except Exception as e:
                rows.append({"where": where, "name": f"(읽기 실패: {type(e).__name__}: {e})"})
        return table("cookies", "쿠키", cols, rows,
                     "Network\\Cookies (앱 루트, 서버 파티션). 값은 Local State 의 os_crypt 키(DPAPI 보호)로 암호화되어 이 도구에서는 풀지 않습니다. "
                     "Rocket.Chat 웹 앱은 로그인 토큰을 쿠키가 아니라 Local Storage 에 둡니다.")


    @staticmethod
    def _cache_kind(url: str) -> str:
        p = urlparse(url).path if url.startswith("http") else url
        if p.startswith("/file-upload/"):
            return "첨부 파일"
        if p.startswith("/avatar/"):
            return "아바타"
        if p.startswith("/api/"):
            return "API 응답"
        if p.startswith("/emoji-custom/"):
            return "사용자 이모지"
        if re.search(r"\.(js|css|woff2?|ttf|svg|png|ico|map)$", p) or p.startswith("/assets/") or p.startswith("/images/"):
            return "정적 자원"
        return "외부" if url.startswith("http") else ""

    def cache(self, app: Path, parts, ctx) -> dict:
        cols = [("time", "캐시 시각 (UTC)"), ("kind", "분류"), ("url", "URL"), ("ctype", "Content-Type"), ("size", "크기(byte)"),
                ("server_date", "서버 응답 시각 (Date)"), ("note", "비고")]
        d = chromium_cache.find_cache_dir(app)
        if d is None:
            return table("cache_entries", "캐시 엔트리", cols, [], "Partitions\\https%3A\\<호스트>\\Cache\\Cache_Data 가 없습니다.")
        rows = []
        cache = ccl_chromium_cache.ChromiumBlockFileCache(d)
        try:
            for key in cache.keys():
                es = cache._keys[key]
                url = chromium_cache.url_of(key)
                row = {"time": fmt_dt(es.creation_time) if es.creation_time and es.creation_time.year > 1601 else "",
                       "kind": self._cache_kind(url), "url": url, "ctype": "", "size": "", "server_date": "", "note": "", "_key": key}
                try:
                    md = (cache.get_metadata(key) or [None])[0]
                    if md:
                        row["ctype"] = ", ".join(md.get_attribute("content-type"))
                        row["server_date"] = ", ".join(md.get_attribute("date"))
                    data = (cache.get_cachefile(key) or [None])[0]
                    row["size"] = len(data) if data is not None else ""
                    if data is None:
                        row["note"] = "본문 없음 (헤더만)"
                except Exception as e:
                    row["note"] = f"읽기 실패: {type(e).__name__}: {e}"
                rows.append(row)
        finally:
            for _, f in cache._block_files.values():
                f.close()
        rows.sort(key=lambda r: r["time"] or "~")
        rel = d.relative_to(app).as_posix() if d.is_relative_to(app) else d.name
        return table("cache_entries", "캐시 엔트리", cols, rows,
                     f"{rel} (Chromium 블록파일 캐시). 아바타(/avatar/<사용자>), 첨부(/file-upload/<id>/<이름>, E2E 첨부는 암호문), API 응답이 남습니다. "
                     "사설 인증서를 신뢰한 서버는 응답을 디스크에 캐시하지 않아 비어 있을 수 있습니다. 행을 누르면 본문을 볼 수 있습니다.")


    LOG_RE = re.compile(r"^\[(?P<t>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?)\]\s*(?:\[(?P<lv>\w+)\])?\s*(?P<msg>.*)$")
    LOG_MEANING = [
        (re.compile(r"Starting Rocket\.Chat Desktop", re.I), "앱 시작"),
        (re.compile(r"Error fetching unique ID", re.I), "서버 연결 시 인증서 오류"),
        (re.compile(r"clipboard\.writeText", re.I), "클립보드 쓰기"),
        (re.compile(r"CA certificates|certificate (error|trusted|not trusted)|trustedCertificates", re.I), "인증서 관련"),
        (re.compile(r"\[downloads?\]|will-download|download (started|completed|finished|failed|cancel)", re.I), "다운로드"),
        (re.compile(r"\[updates?\]|update-(available|downloaded|not-available)|checking for update", re.I), "업데이트"),
        (re.compile(r"initialization completed", re.I), "앱 초기화 완료"),
        (re.compile(r"\[renderer:", re.I), "렌더러(화면) 경고"),
    ]

    def logs(self, app: Path, parts, ctx) -> list[dict]:
        cols = [("time", "시각 (로컬)"), ("file", "파일"), ("level", "수준"), ("meaning", "해석"), ("message", "내용"), ("extra", "이어지는 줄")]
        d = app / "logs"
        rows = []
        for f in sorted(d.glob("*.log")) if d.is_dir() else []:
            cur = None
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                m = self.LOG_RE.match(line)
                if m:
                    msg = m["msg"]
                    cur = {"time": m["t"].replace("T", " "), "file": f.name, "level": m["lv"] or "",
                           "meaning": next((v for k, v in self.LOG_MEANING if k.search(msg)), ""),
                           "message": msg[:4000], "extra": "", "_n": 0}
                    rows.append(cur)
                    if "Starting Rocket.Chat Desktop" in msg:
                        mv = re.search(r"(\d+\.\d+\.\d+)", msg)
                        if mv:
                            ctx["counts"].setdefault("app_version", mv[1])
                elif cur is not None and line.strip():
                    cur["_n"] += 1
                    if cur["_n"] <= 20:
                        cur["extra"] += ("\n" if cur["extra"] else "") + line[:500]
        for r in rows:
            n = r.pop("_n")
            if n > 20:
                r["extra"] += f"\n… (이어지는 줄 {n}줄 중 20줄만 표시)"
        e_cols = [("time", "시각 (UTC)"), ("raw_time", "시각 원문 (해석 못 함)"), ("level", "수준"), ("message", "내용"), ("detail", "세부")]
        erows = []
        ef = d / "errors.jsonl"
        if ef.is_file():
            for line in ef.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    j = json.loads(line)
                except ValueError:
                    erows.append({"message": line[:2000]})
                    continue
                if not isinstance(j, dict):
                    continue
                ts = j.get("timestamp") or j.get("time") or ""
                erows.append({"time": tstr(ts), "raw_time": "" if tstr(ts) else str(ts), "level": str(j.get("level", "")),
                              "message": str(j.get("message") or j.get("text") or j.get("error") or j.get("msg") or "")[:2000],
                              "detail": jdump({k: v for k, v in j.items() if k not in ("timestamp", "time", "level", "message", "text")}, 3000)})
        return [
            table("app_log", "앱 로그 (main.log)", cols, rows,
                  "logs\\main.log. 시각은 PC 로컬 시간(문서 사례 KST)입니다. 'Starting Rocket.Chat Desktop' = 앱 시작, "
                  "'Error fetching unique ID for server' = 서버 연결 때 인증서 오류, clipboard.writeText = 클립보드 쓰기. 스택 줄은 '이어지는 줄'에 묶었습니다."),
            table("errors_log", "렌더러 오류 (errors.jsonl)", e_cols, erows, "logs\\errors.jsonl. 시각은 UTC 입니다."),
        ]


    def chromium(self, app: Path, parts, ctx) -> dict:
        items = {}

        def load(name):
            f = app / name
            if not f.is_file():
                return None
            try:
                return json.loads(f.read_text(encoding="utf-8", errors="replace"))
            except ValueError:
                return None

        ls = load("Local State") or {}
        enc = ((ls.get("os_crypt") or {}).get("encrypted_key")) or ""
        if enc:
            try:
                raw = base64.b64decode(enc)
                items["os_crypt.encrypted_key"] = f"{len(raw)} B, 접두어 {raw[:5].decode('latin1')!r} (DPAPI 로 보호한 쿠키, 비밀번호 키)"
            except ValueError:
                items["os_crypt.encrypted_key"] = f"{len(enc)}자 (base64 해석 실패)"
        um = ls.get("uninstall_metrics") or {}
        if um.get("installation_date2"):
            try:
                items["첫 실행 (uninstall_metrics.installation_date2, UTC)"] = fmt_ms(int(um["installation_date2"]) * 1000)
            except ValueError:
                items["첫 실행 (installation_date2)"] = str(um["installation_date2"])
        pref = load("Preferences") or {}
        sc = pref.get("spellcheck") or {}
        if sc:
            items["맞춤법 언어 (Preferences spellcheck.dictionaries)"] = ", ".join(map(str, sc.get("dictionaries") or [])) or jdump(sc, 300)
        dl = (pref.get("download") or {}).get("default_directory")
        if dl:
            items["다운로드 폴더 (Preferences)"] = dl
        nps = load("Network/Network Persistent State") or load("Network Persistent State") or {}
        hsp = nps.get("net", {}).get("http_server_properties", {}) if isinstance(nps.get("net"), dict) else {}
        quic = hsp.get("supports_quic") or {}
        if quic.get("address"):
            items["로컬 IP (Network Persistent State supports_quic.address)"] = quic["address"]
        servers = [s.get("server", "") for s in hsp.get("servers") or [] if isinstance(s, dict)]
        if servers:
            items["접속한 서버 (http_server_properties.servers)"] = ", ".join(servers[:50])
        items["서버 파티션"] = ", ".join(f"{srv} ({p.relative_to(app).as_posix()})" for srv, p in parts) or "없음"
        return kv("chromium", "Chromium 공통 설정", items,
                  "Local State, Preferences (앱 루트), Network\\Network Persistent State (구버전은 앱 루트). 첫 실행 시각, 맞춤법 언어, 분석 대상 PC 의 로컬 IP 를 확인합니다.")


    FINDINGS_DESC = (
        "이 PC 의 앱 데이터에 남은 삭제, 편집 정황만 모았습니다. 확실 = 기록으로 확인되는 사실, 추정 = 정황. "
        "점검 항목: Local Storage 에서 지워진 키(저장소 점검용 _localstorage_test_*, 전송하면 비워지는 입력창 초안 messagebox_*, "
        "로그아웃 때 지워지는 Meteor.* 로그인 키 제외), "
        "IndexedDB lastMessage 에 남은 편집, 삭제 표시. 서버 기록과의 대조(지워진 메시지의 원문, E2E 평문 등)는 좌측 '교차 분석'에서 봅니다."
    )

    LS_ROUTINE = ("_localstorage_test_", "messagebox_", "Meteor.")

    def findings(self, sections: list[dict]) -> list[dict]:
        S = {s["id"]: s for s in sections if s.get("type") == "table"}
        rows_of = lambda sid: S[sid]["rows"] if sid in S else []
        out, seen = [], set()
        for r in rows_of("localstorage"):
            key = r.get("key") or ""
            k = (r.get("server"), key, r.get("seq"))
            if r.get("state") != "deleted" or key.startswith(self.LS_ROUTINE) or k in seen:
                continue
            seen.add(k)
            out.append(finding(CERTAIN, "앱 저장소 키 삭제", r.get("time"), f"{r.get('server')}, {key}",
                               f"Local Storage 에서 지워진 키입니다 (seq {r.get('seq')}). {r.get('meaning') or ''}".strip(),
                               "Local Storage", {"section": "localstorage", "match": {"seq": r.get("seq"), "key": key}}, "deleted"))
        for r in rows_of("messages"):
            k = (r.get("id"), r.get("edited"), r.get("type"))
            if k in seen:
                continue
            t = f"message {r.get('id')}, {r.get('user')}, {r.get('room')}"
            mref = {"section": "messages", "match": {"id": r.get("id"), "state": r.get("state")}}
            if r.get("type") == "rm":
                seen.add(k)
                out.append(finding(CERTAIN, "메시지 삭제 표시 (클라이언트)", r.get("updated") or r.get("ts"), t,
                                   "lastMessage 가 삭제된 메시지(t=rm)로 바뀐 기록입니다. 같은 id 의 이전 판에 삭제 전 내용이 남을 수 있습니다.",
                                   "메시지 이력", mref, "softdel"))
            elif r.get("edited"):
                seen.add(k)
                out.append(finding(CERTAIN, "메시지 편집 (클라이언트)", (r.get("edited") or "").split(" by ")[0], t,
                                   f"lastMessage 에 편집 표시(editedAt {r.get('edited')})가 있습니다. 내용: \"{short(r.get('plain') or r.get('msg'))}\"",
                                   "메시지 이력", mref, "updated"))
        return out

from __future__ import annotations

import gzip
import json
import re
import sqlite3
import zlib
from pathlib import Path

from ..base import (CERTAIN, BaseParser, error_section, finding, fmt_dt, fmt_ms, fmt_webkit, kv, short,
                    split_label, table)

import backend.vendor
from ccl_chromium_reader import ccl_chromium_cache, ccl_chromium_indexeddb, ccl_chromium_localstorage

ID_RE = re.compile(r"^[a-z0-9]{26}$")
EMPTY_DRAFT = "(비어 있음)"
CHANNEL_TYPES = {"O": "공개", "P": "비공개", "D": "DM", "G": "그룹 DM"}


def find_app_dir(root: Path) -> Path:
    candidates = [root] + [p.parent for p in root.rglob("config.json")]
    for d in candidates:
        if (d / "config.json").is_file() and ((d / "Local Storage").is_dir() or (d / "IndexedDB").is_dir()):
            return d
    for d in candidates:
        if (d / "IndexedDB").is_dir() or (d / "Local Storage").is_dir():
            return d
    return root


class Names:
    def __init__(self):
        self.users: dict[str, str] = {}
        self.channels: dict[str, dict] = {}
        self.teams: dict[str, str] = {}

    def collect(self, obj):
        if isinstance(obj, list):
            for x in obj:
                self.collect(x)
            return
        if not isinstance(obj, dict):
            return
        oid = obj.get("id")
        if isinstance(oid, str) and ID_RE.match(oid):
            if "username" in obj:
                self.users[oid] = obj["username"]
            elif "display_name" in obj and "type" in obj and "team_id" in obj:
                self.channels[oid] = {"name": obj.get("name", ""), "display": obj.get("display_name", ""),
                                      "type": obj.get("type", "")}
            elif "display_name" in obj and "company_name" in obj or ("invite_id" in obj and "name" in obj):
                self.teams[oid] = obj.get("display_name") or obj.get("name", "")
        for v in obj.values():
            if isinstance(v, (dict, list)):
                self.collect(v)

    def user(self, uid: str) -> str:
        return f"{self.users[uid]} ({uid})" if uid in self.users else (uid or "")

    def channel(self, cid: str) -> str:
        c = self.channels.get(cid)
        if not c:
            return cid or ""
        if c["type"] == "D":
            names = [self.users.get(u, u[:8]) for u in c["name"].split("__")]
            return f"DM: {', '.join(names)} ({cid})"
        return f"{c['display'] or c['name']} ({cid})"


class MattermostClientParser(BaseParser):
    mode = "client"
    app = "mattermost"
    is_dummy = False

    def parse(self, root: Path, inventory: list[dict]) -> dict:
        app = find_app_dir(root)
        names = Names()
        sections = []
        counts = {}

        try:
            cache_entries, cache_posts = self.cache(app, names)
        except Exception as e:
            cache_entries, cache_posts = None, None
            cache_err = e

        for fn in (self.config, self.app_state):
            try:
                sections.extend(fn(app, counts))
            except Exception as e:
                sections.append(error_section(fn.__name__, "앱 설정", e))

        for fn, title in ((self.local_storage, "Local Storage"), (self.drafts, "작성 중 드래프트")):
            try:
                sections.append(fn(app, names, counts))
            except Exception as e:
                sections.append(error_section(fn.__name__, title, e))

        if cache_entries is None:
            sections.append(error_section("cache", "캐시", cache_err))
        else:
            counts["cache_posts"] = len(cache_posts["rows"])
            counts["cache_entries"] = len(cache_entries["rows"])
            sections += [cache_posts, cache_entries]

        for fn, title in ((self.cookies, "쿠키"), (self.main_log, "앱 로그")):
            try:
                sections.append(fn(app, counts))
            except Exception as e:
                sections.append(error_section(fn.__name__, title, e))

        summary = [
            {"label": "접속 서버", "value": counts.get("servers", 0)},
            {"label": "드래프트", "value": counts.get("drafts", 0)},
            {"label": "캐시 복원 메시지", "value": counts.get("cache_posts", 0)},
            {"label": "캐시 엔트리", "value": counts.get("cache_entries", 0)},
            {"label": "Local Storage 레코드", "value": counts.get("localstorage", 0)},
            {"label": "인증 쿠키", "value": counts.get("cookies", 0)},
        ]
        return {"summary": summary, "sections": sections}


    LS_ROUTINE = ("__login__", "__testLocal__")

    FINDINGS_DESC = (
        "이 PC 의 앱 데이터에 남은 삭제, 편집 정황만 모았습니다. 확실 = 기록으로 확인되는 사실, 추정 = 정황. "
        "점검 항목: Local Storage 에서 지워진 키(앱이 늘 쓰고 지우는 __login__, __testLocal__ 제외), "
        "캐시된 서버 응답 속 삭제, 편집된 메시지. 서버 기록과의 대조는 좌측 '교차 분석'에서 봅니다 (Server 증거도 올린 경우)."
    )

    def findings(self, sections: list[dict]) -> list[dict]:
        S = {s["id"]: s for s in sections if s.get("type") == "table"}
        rows_of = lambda sid: S[sid]["rows"] if sid in S else []
        out = []
        for r in rows_of("localstorage"):
            if r.get("state") == "deleted" and r.get("key") not in self.LS_ROUTINE:
                out.append(finding(CERTAIN, "앱 저장소 키 삭제", r.get("time"), f"{r.get('origin')}, {r.get('key')}",
                                   f"Local Storage 에서 지워진 키입니다 (seq {r.get('seq')}). {r.get('meaning') or ''}".strip(),
                                   "Local Storage", {"section": "localstorage", "match": {"seq": r.get("seq")}}, "deleted"))
        for r in rows_of("cache_posts"):
            t = f"post {r.get('post_id')}, {split_label(r.get('user'))[0]}, {split_label(r.get('channel'))[0]}"
            ref = {"section": "cache_posts", "match": {"post_id": r.get("post_id")}}
            if r.get("delete"):
                out.append(finding(CERTAIN, "메시지 삭제 (캐시)", r.get("delete"), t,
                                   f"캐시된 서버 응답에 삭제 표시(delete_at)가 있습니다. 캐시 시각 {r.get('cached')}. 내용: \"{short(r.get('message'))}\"",
                                   "캐시 메시지", ref, "softdel"))
            if r.get("edit"):
                out.append(finding(CERTAIN, "메시지 편집 (캐시)", r.get("edit"), t,
                                   f"캐시된 서버 응답에 편집 표시(edit_at)가 있습니다. 캐시된 내용: \"{short(r.get('message'))}\"",
                                   "캐시 메시지", ref, "updated"))
        return out


    def config(self, app: Path, counts: dict) -> list[dict]:
        f = app / "config.json"
        if not f.is_file():
            return [error_section("config", "앱 설정", "config.json 이 없습니다")]
        cfg = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        servers = cfg.get("servers") or cfg.get("teams") or []
        last = cfg.get("lastActiveServer", cfg.get("lastActiveTeam"))
        rows = [{"order": s.get("order", i), "name": s.get("name", ""), "url": s.get("url", ""),
                 "predefined": str(s.get("isPredefined", "")).lower(),
                 "last": "마지막 활성" if i == last else ""}
                for i, s in enumerate(servers)]
        counts["servers"] = len(rows)
        settings = {
            "config 버전": cfg.get("version", ""),
            "마지막 활성 서버 (lastActiveServer)": last if last is not None else "",
            "다운로드 경로 (downloadLocation)": cfg.get("downloadLocation", ""),
            "자동 시작 (autostart)": cfg.get("autostart", ""),
            "트레이 최소화 (minimizeToTray)": cfg.get("minimizeToTray", ""),
            "맞춤법 검사 (useSpellChecker)": cfg.get("useSpellChecker", ""),
        }
        return [
            table("servers", "접속 서버", [("order", "순서"), ("name", "이름"), ("url", "URL"),
                                         ("last", "상태"), ("predefined", "사전 등록")], rows,
                  "config.json 의 servers 배열 (구버전은 teams)."),
            kv("app_config", "앱 설정", {k: str(v) for k, v in settings.items()}, "config.json"),
        ]

    def app_state(self, app: Path, counts: dict) -> list[dict]:
        f = app / "app-state.json"
        if not f.is_file():
            return []
        st = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        return [kv("app_state", "앱 버전", {"마지막 실행 앱 버전 (lastAppVersion)": st.get("lastAppVersion", "")},
                   "app-state.json")]


    def local_storage(self, app: Path, names: Names, counts: dict) -> dict:
        d = app / "Local Storage" / "leveldb"
        cols = [("seq", "seq"), ("state", "상태"), ("time", "기록 시각 (UTC)"), ("origin", "origin"),
                ("key", "키"), ("meaning", "의미"), ("value", "값")]
        if not d.is_dir():
            return table("localstorage", "Local Storage", cols, [], "Local Storage\\leveldb 폴더가 없습니다.")
        db = ccl_chromium_localstorage.LocalStoreDb(d)
        try:
            recs = sorted(db.iter_all_records(include_deletions=True), key=lambda r: r.leveldb_seq_number)
            rows = []
            for r in recs:
                batch = db.find_batch(r.leveldb_seq_number)
                rows.append({
                    "seq": r.leveldb_seq_number,
                    "state": "live" if r.is_live else "deleted",
                    "time": fmt_dt(batch.timestamp) if batch else "",
                    "origin": r.storage_key,
                    "key": r.script_key,
                    "meaning": self._ls_meaning(r.script_key, names),
                    "value": r.value if r.value is not None else "",
                })
        finally:
            db.close()
        counts["localstorage"] = len(rows)
        return table("localstorage", "Local Storage", cols, rows,
                     "로그인 흔적, 마지막 팀, 방문 채널. 같은 키의 이전 값과 삭제 기록도 seq 순으로 남아 있습니다.",
                     row_class="state")

    @staticmethod
    def _ls_meaning(key: str, names: Names) -> str:
        parts = key.split(":")
        user = names.user(parts[1]) if len(parts) > 1 else ""
        if key == "was_logged_in":
            return "로그인 이력"
        if key == "was_notified_of_login":
            return "로그인 알림 표시 여부"
        if key.startswith("user_prev_team:"):
            return f"마지막 사용 팀 (사용자 {user})"
        if key.startswith("user_team_prev_channel:"):
            return f"마지막 방문 채널 (사용자 {user})"
        if key.startswith("user_team_penultimate_channel:"):
            return f"직전 방문 채널 (사용자 {user})"
        if key.startswith(("user_team_prev_viewed_type:", "user_team_penultimate_viewed_type:")):
            return "방문 화면 종류"
        if key.startswith("__announcement__"):
            return "공지 배너 표시 기록"
        if key.startswith("_localforage"):
            return "localforage 내부 (IndexedDB 저장소 정보)"
        return ""


    def drafts(self, app: Path, names: Names, counts: dict) -> dict:
        cols = [("kind", "종류"), ("state", "상태"), ("channel", "채널"), ("root", "스레드 루트 글"),
                ("message", "메시지"), ("create", "작성 시각 (UTC)"), ("update", "수정 시각 (UTC)"),
                ("saved", "저장 시각 (UTC)"), ("seq", "seq (처음~마지막)"), ("key", "키")]
        idb_root = app / "IndexedDB"
        dirs = sorted(idb_root.glob("*.indexeddb.leveldb")) if idb_root.is_dir() else []
        if not dirs:
            return table("drafts", "작성 중 드래프트", cols, [], "IndexedDB 폴더가 없습니다.")

        found: dict[tuple, dict] = {}
        latest: dict[str, tuple] = {}
        latest_seq = -1
        for d in dirs:
            idb = ccl_chromium_indexeddb.WrappedIndexDB(d)
            for dbid in idb.database_ids:
                db = idb[dbid.dbid_no]
                for sname in db.object_store_names:
                    store = db.get_object_store_by_name(sname)
                    for rec in store.iterate_records(bad_deserializer_data_handler=lambda k, v: None):
                        if not isinstance(rec.value, str) or "draft_" not in rec.value:
                            continue
                        try:
                            obj = json.loads(rec.value)
                        except ValueError:
                            continue
                        snapshot = {}
                        for k, v in obj.items():
                            if not (k.startswith("draft_") or k.startswith("comment_draft_")):
                                continue
                            try:
                                dv = json.loads(v) if isinstance(v, str) else v
                            except ValueError:
                                continue
                            val = dv.get("value") or {}
                            msg = val.get("message", "")
                            ident = (k, msg, val.get("updateAt"))
                            snapshot[k] = ident
                            row = found.get(ident)
                            if row is None:
                                cid = val.get("channelId") or k.split("_")[-1]
                                found[ident] = row = {
                                    "kind": "스레드 답글" if k.startswith("comment_draft_") else "채널 메시지",
                                    "channel": names.channel(cid),
                                    "root": val.get("rootId", "") or (k.split("_")[-1] if k.startswith("comment_") else ""),
                                    "message": msg if msg else EMPTY_DRAFT,
                                    "create": fmt_ms(val.get("createAt")),
                                    "update": fmt_ms(val.get("updateAt")),
                                    "saved": (dv.get("timestamp") or "").replace("T", " ").rstrip("Z"),
                                    "_first": rec.ldb_seq_no, "_last": rec.ldb_seq_no, "key": k,
                                }
                            row["_first"] = min(row["_first"], rec.ldb_seq_no)
                            row["_last"] = max(row["_last"], rec.ldb_seq_no)
                        if rec.is_live and rec.ldb_seq_no > latest_seq:
                            latest_seq, latest = rec.ldb_seq_no, snapshot

        current = set(latest.values())
        rows = []
        for ident, r in found.items():
            is_current = ident in current
            r["state"] = "현재 값" if is_current else "이전 값"
            r["_state"] = "" if is_current else "updated"
            r["seq"] = f"{r.pop('_first')}~{r.pop('_last')}"
            rows.append(r)
        rows.sort(key=lambda r: (r["update"] or r["saved"]))
        counts["drafts"] = sum(1 for r in rows if r["message"] != EMPTY_DRAFT)
        return table("drafts", "작성 중 드래프트", cols, rows,
                     "IndexedDB persist:storage 의 draft_<채널ID>(채널), comment_draft_<루트글ID>(스레드 답글). "
                     "저장될 때마다 새 레코드가 쌓여 이전 값도 복원됩니다. '(비어 있음)'은 전송 후 비워진 드래프트입니다.",
                     row_class="_state")


    def cache(self, app: Path, names: Names) -> tuple[dict, dict]:
        d = app / "Cache" / "Cache_Data"
        e_cols = [("time", "캐시 시각 (UTC)"), ("url", "URL"), ("ctype", "Content-Type"),
                  ("encoding", "인코딩"), ("size", "크기(byte)"), ("location", "저장 위치"), ("note", "비고")]
        p_cols = [("create", "작성 시각 (UTC)"), ("channel", "채널"), ("user", "작성자"), ("message", "메시지"),
                  ("type", "유형"), ("root", "스레드 루트"), ("edit", "편집 시각"), ("delete", "삭제 시각"),
                  ("post_id", "post id"), ("cached", "캐시 시각 (UTC)"), ("hits", "응답 수"), ("url", "출처 URL")]
        if not (d / "index").is_file():
            msg = "Cache\\Cache_Data\\index 가 없습니다."
            return table("cache_entries", "캐시 엔트리", e_cols, [], msg), table("cache_posts", "캐시 메시지", p_cols, [], msg)

        cache = ccl_chromium_cache.ChromiumBlockFileCache(d)
        entries, bodies = [], []
        try:
            for key in cache.keys():
                es = cache._keys[key]
                url = key.split(" ")[-1]
                url = url[url.find("http"):] if "http" in url else url
                row = {"time": fmt_dt(es.creation_time), "url": url, "ctype": "", "encoding": "",
                       "size": "", "location": "", "note": "", "_key": key}
                try:
                    md = (cache.get_metadata(key) or [None])[0]
                    if md:
                        row["ctype"] = ", ".join(md.get_attribute("content-type"))
                        row["encoding"] = ", ".join(md.get_attribute("content-encoding"))
                    loc = (cache.get_location_for_cachefile(key) or [None])[0]
                    if loc:
                        row["location"] = f"{loc.file_name} @ {loc.offset}"
                    data = (cache.get_cachefile(key) or [None])[0]
                    if data is not None:
                        row["size"] = len(data)
                        body, note = self._decode_body(data, row["encoding"])
                        row["note"] = note
                        if body is not None and "json" in row["ctype"]:
                            bodies.append((url, es.creation_time, body))
                except Exception as e:
                    row["note"] = f"읽기 실패: {type(e).__name__}: {e}"
                entries.append(row)
        finally:
            for _, f in cache._block_files.values():
                f.close()

        parsed = []
        for url, t, body in bodies:
            try:
                obj = json.loads(body)
            except ValueError:
                continue
            names.collect(obj)
            parsed.append((url, t, obj))

        posts: dict[str, dict] = {}
        for url, t, obj in parsed:
            for p in self._iter_posts(obj):
                pid = p["id"]
                cur = posts.get(pid)
                if cur is None or (p.get("update_at") or 0) > (cur["_p"].get("update_at") or 0):
                    posts[pid] = {"_p": p, "_url": url, "_t": t, "_hits": (cur or {}).get("_hits", 0)}
                posts[pid]["_hits"] = posts[pid].get("_hits", 0) + 1

        p_rows = []
        for pid, v in posts.items():
            p = v["_p"]
            p_rows.append({
                "create": fmt_ms(p.get("create_at")), "channel": names.channel(p.get("channel_id", "")),
                "user": names.user(p.get("user_id", "")), "message": p.get("message", ""),
                "type": p.get("type", ""), "root": p.get("root_id", ""),
                "edit": fmt_ms(p.get("edit_at")), "delete": fmt_ms(p.get("delete_at")),
                "post_id": pid, "cached": fmt_dt(v["_t"]), "hits": v["_hits"], "url": v["_url"],
                "_state": "deleted" if (p.get("delete_at") or 0) > 0 else "",
            })
        p_rows.sort(key=lambda r: r["create"])
        entries.sort(key=lambda r: r["time"])
        return (
            table("cache_entries", "캐시 엔트리", e_cols, entries,
                  "Chromium 블록파일 캐시(index, data_0~3, f_*). GET 으로 받은 서버 응답이 평문 또는 gzip 으로 남습니다."),
            table("cache_posts", "캐시 메시지", p_cols, p_rows,
                  "캐시된 API 응답(/api/v4/posts, channels/…/posts 등)에서 복원한 메시지. 상대가 보낸 수신 메시지도 포함됩니다. "
                  "같은 글이 여러 응답에 있으면 가장 최근 수정본을 보여 줍니다.", row_class="_state"),
        )

    @staticmethod
    def _decode_body(data: bytes, encoding: str) -> tuple[str | None, str]:
        enc = encoding.lower()
        try:
            if data[:2] == b"\x1f\x8b" or "gzip" in enc:
                return gzip.decompress(data).decode("utf-8", "replace"), "gzip 해제"
            if "deflate" in enc:
                return zlib.decompress(data).decode("utf-8", "replace"), "deflate 해제"
            if "br" in enc.split(", "):
                try:
                    import brotli
                except ImportError:
                    return None, "brotli 압축 (미지원 - brotli 패키지 필요)"
                return brotli.decompress(data).decode("utf-8", "replace"), "brotli 해제"
        except Exception as e:
            return None, f"압축 해제 실패: {type(e).__name__}"
        return data.decode("utf-8", "replace"), ""

    @staticmethod
    def _iter_posts(obj):
        if isinstance(obj, dict):
            if isinstance(obj.get("posts"), dict):
                for p in obj["posts"].values():
                    if isinstance(p, dict) and "message" in p and "id" in p:
                        yield p
            elif "message" in obj and "channel_id" in obj and "create_at" in obj and "id" in obj:
                yield obj
        elif isinstance(obj, list):
            for x in obj:
                if isinstance(x, dict) and "message" in x and "channel_id" in x and "id" in x:
                    yield x


    def cookies(self, app: Path, counts: dict) -> dict:
        f = app / "Network" / "Cookies"
        if not f.is_file():
            f = app / "Cookies"
        cols = [("host", "호스트"), ("name", "이름"), ("created", "생성 (UTC)"), ("expires", "만료 (UTC)"),
                ("last_access", "마지막 접근 (UTC)"), ("secure", "secure"), ("httponly", "httponly"),
                ("persistent", "영속"), ("value", "평문 값"), ("encrypted", "암호문")]
        if not f.is_file():
            return table("cookies", "쿠키", cols, [], "Network\\Cookies 가 없습니다.")
        con = sqlite3.connect(f"file:{f.as_posix()}?mode=ro&immutable=1", uri=True)
        try:
            con.row_factory = sqlite3.Row
            rows = []
            for r in con.execute("SELECT * FROM cookies ORDER BY creation_utc"):
                r = dict(r)
                enc = r.get("encrypted_value") or b""
                rows.append({
                    "host": r.get("host_key", ""), "name": r.get("name", ""),
                    "created": fmt_webkit(r.get("creation_utc")), "expires": fmt_webkit(r.get("expires_utc")),
                    "last_access": fmt_webkit(r.get("last_access_utc")),
                    "secure": r.get("is_secure", ""), "httponly": r.get("is_httponly", ""),
                    "persistent": r.get("is_persistent", ""), "value": r.get("value", ""),
                    "encrypted": f"{len(enc)} bytes (접두어 {enc[:3].decode('latin1')!r})" if enc else "",
                })
        finally:
            con.close()
        counts["cookies"] = sum(1 for r in rows if r["name"] in ("MMAUTHTOKEN", "MMCSRF", "MMUSERID"))
        return table("cookies", "쿠키", cols, rows,
                     "Chromium 쿠키 DB. MMAUTHTOKEN, MMCSRF, MMUSERID 는 OS 암호화(DPAPI, 접두어 v10)로 보호되어 암호문만 남습니다. "
                     "만료 시각은 서버 sessions 테이블의 세션 만료와 일치합니다.")


    def main_log(self, app: Path, counts: dict) -> dict:
        cols = [("time", "시각 (로컬)"), ("level", "수준"), ("source", "모듈"), ("message", "내용")]
        logs = sorted((app / "logs").glob("*.log")) if (app / "logs").is_dir() else []
        rows = []
        pat = re.compile(r"^\[(?P<t>[\d\- :.]+)\]\s+\[(?P<lv>\w+)\]\s+(?:\[(?P<src>[^\]]+)\]\s*)?(?P<msg>.*)$")
        for f in logs:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                m = pat.match(line)
                if m:
                    rows.append({"time": m["t"], "level": m["lv"], "source": m["src"] or "", "message": m["msg"]})
                elif rows and line.strip():
                    rows[-1]["message"] += "\n" + line
        return table("main_log", "앱 로그", cols, rows,
                     "logs\\main.log. 시각은 PC 로컬 시간입니다. SecureStorage 초기화 기록으로 비밀값이 OS 암호화 저장소를 쓰는지 확인할 수 있습니다.")

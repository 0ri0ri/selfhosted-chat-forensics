from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

from ...artifacts import chromium_cache
from ..base import CERTAIN, BaseParser, error_section, finding, fmt_dt, fmt_ms, fmt_webkit, kv, table

import backend.vendor
from ccl_chromium_reader import ccl_chromium_cache, ccl_chromium_localstorage


def find_app_dir(root: Path) -> Path:
    for f in sorted(root.rglob("domain.json"), key=lambda p: len(p.parts)):
        if f.parent.name == "config":
            return f.parent.parent
    for d in sorted(root.rglob("webviewsession"), key=lambda p: len(p.parts)):
        if d.is_dir() and d.parent.name == "Partitions":
            return d.parent.parent
    return root


def find_partitions(app: Path) -> list[Path]:
    d = app / "Partitions"
    if not d.is_dir():
        return []
    parts = [p for p in d.iterdir() if p.is_dir()]
    return sorted(parts, key=lambda p: (p.name != "webviewsession", p.name))


def decode_hash(s: str) -> str:
    return unquote(re.sub(r"\.([0-9A-Fa-f]{2})", r"%\1", s))


def describe_zulip_url(url: str) -> str:
    try:
        frag = urlparse(url).fragment
    except ValueError:
        return ""
    if not frag:
        path = urlparse(url).path
        if path.startswith("/login"):
            return "로그인 화면"
        if path in ("", "/"):
            return "웹앱 메인 화면"
        return ""
    parts = frag.split("/")
    head = parts[0]
    if head == "narrow":
        ops = parts[1:]
        out = []
        for i in range(0, len(ops) - 1, 2):
            op, val = ops[i], decode_hash(ops[i + 1])
            if op in ("channel", "stream"):
                m = re.match(r"^(\d+)-?(.*)$", val)
                out.append(f"채널 id {m[1]} ({m[2]})" if m else f"채널 {val}")
            elif op == "topic":
                out.append(f"토픽 '{val}'" if val else "토픽 '' (빈 토픽 = general chat)")
            elif op in ("with", "near"):
                out.append(f"메시지 id {val}")
            elif op in ("dm", "pm-with"):
                out.append(f"DM 대상 {val}")
            elif op == "is":
                out.append(f"필터 is:{val}")
            elif op == "search":
                out.append(f"검색어 '{val}'")
            else:
                out.append(f"{op}:{val}")
        return "메시지 보기 - " + ", ".join(out) if out else "메시지 보기"
    known = {"channels/new": "채널 만들기 화면", "channels": "채널 목록", "settings": "개인 설정",
             "organization": "조직 설정", "inbox": "받은 편지함(Inbox)", "recent": "최근 대화",
             "feed": "통합 피드", "drafts": "초안 목록", "scheduled": "예약 메시지", "invite": "초대"}
    for k in sorted(known, key=len, reverse=True):
        if frag == k or frag.startswith(k + "/"):
            return known[k] + (f" ({frag})" if frag != k else "")
    return frag


LS_MEANING = {
    "drafts": "미전송 초안",
    "left_sidebar_collapsed_stream_sections": "왼쪽 사이드바: 접힌 채널 섹션",
    "left_sidebar_direct_messages_collapsed_state": "왼쪽 사이드바: DM 섹션 접힘 여부",
    "tusSupport": "업로드(tus) 지원 확인용 임시 키 - 쓰고 바로 지움",
}


class ZulipClientParser(BaseParser):
    mode = "client"
    app = "zulip"
    is_dummy = False

    def parse(self, root: Path, inventory: list[dict]) -> dict:
        app = find_app_dir(root)
        parts = find_partitions(app)
        sections: list[dict] = []
        counts: dict = {}

        steps = [
            (self.domains, "접속 서버"),
            (self.settings, "앱 설정"),
            (self.sentry, "실행 환경, 화면 이동 (sentry)"),
            (self.cookies, "쿠키"),
            (self.local_storage, "Local Storage"),
            (self.cache, "캐시"),
            (self.app_logs, "앱 로그"),
        ]
        for fn, title in steps:
            try:
                out = fn(app, parts, counts)
                sections.extend(out if isinstance(out, list) else [out])
            except Exception as e:
                sections.append(error_section(fn.__name__, title, e))

        summary = [
            {"label": "접속 서버", "value": counts.get("servers", 0)},
            {"label": "서버 버전", "value": counts.get("server_version") or "-"},
            {"label": "앱 버전", "value": counts.get("app_version") or "-"},
            {"label": "세션 쿠키", "value": counts.get("cookies", 0)},
            {"label": "미전송 초안", "value": counts.get("drafts", 0)},
            {"label": "화면 이동 기록", "value": counts.get("nav", 0)},
            {"label": "캐시 엔트리", "value": counts.get("cache_entries", 0)},
        ]
        return {"summary": summary, "sections": sections}


    def domains(self, app: Path, parts, counts) -> list[dict]:
        f = app / "config" / "domain.json"
        cols = [("alias", "조직 별칭"), ("url", "서버 URL"), ("version", "서버 버전 (zulipVersion)"),
                ("level", "기능 레벨"), ("icon", "아이콘 파일"), ("icon_ok", "아이콘 파일 존재")]
        if not f.is_file():
            return [table("servers", "접속 서버", cols, [], "config\\domain.json 이 없습니다.")]
        cfg = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        rows = []
        for d in cfg.get("domains") or []:
            icon = d.get("icon") or ""
            name = re.split(r"[\\/]", icon)[-1] if icon else ""
            rows.append({"alias": d.get("alias", ""), "url": d.get("url", ""),
                         "version": d.get("zulipVersion", ""), "level": d.get("zulipFeatureLevel", ""),
                         "icon": icon,
                         "icon_ok": ("있음" if (app / "server-icons" / name).is_file() else "없음") if name else ""})
        counts["servers"] = len(rows)
        if rows:
            counts["server_version"] = rows[0]["version"]
        return [table("servers", "접속 서버", cols, rows,
                      "config\\domain.json. 앱에 추가한 서버(조직)의 URL, 별칭과, 추가할 때 서버가 알려 준 버전입니다. "
                      "서버 아이콘은 server-icons 폴더에 저장됩니다.")]


    SETTING_LABELS = {
        "downloadsPath": "다운로드 폴더", "promptDownload": "다운로드마다 위치 묻기",
        "errorReporting": "오류 보고 (Sentry)", "autoUpdate": "자동 업데이트", "betaUpdate": "베타 업데이트",
        "showNotification": "알림 표시", "silent": "알림 소리 끔", "dnd": "방해 금지", "trayIcon": "트레이 아이콘",
        "startAtLogin": "로그인 시 자동 시작", "startMinimized": "최소화 상태로 시작", "quitOnClose": "창 닫으면 종료",
        "lastActiveTab": "마지막 활성 서버 탭 (domain.json 순번)", "appLanguage": "앱 언어",
        "enableSpellchecker": "맞춤법 검사", "spellcheckerLanguages": "맞춤법 언어",
        "useManualProxy": "수동 프록시", "useSystemProxy": "시스템 프록시", "proxyRules": "프록시 규칙",
        "proxyPAC": "프록시 PAC", "proxyBypass": "프록시 예외", "customCSS": "사용자 CSS",
        "flashTaskbarOnMessage": "새 메시지 시 작업표시줄 깜빡임", "badgeOption": "읽지 않음 배지",
        "showSidebar": "서버 사이드바 표시", "autoHideMenubar": "메뉴바 자동 숨김",
        "dndPreviousSettings": "방해 금지 이전 설정",
    }

    def settings(self, app: Path, parts, counts) -> list[dict]:
        out = []
        f = app / "config" / "settings.json"
        if f.is_file():
            cfg = json.loads(f.read_text(encoding="utf-8", errors="replace"))
            items = {}
            for k, v in cfg.items():
                label = self.SETTING_LABELS.get(k)
                val = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) or v is None else str(v)
                items[f"{label} ({k})" if label else k] = val
            out.append(kv("app_settings", "앱 설정", items,
                          "config\\settings.json. 오류 보고가 켜져 있으면 sentry 폴더에 실행 환경과 화면 이동 기록이 남습니다."))
        else:
            out.append(error_section("app_settings", "앱 설정", "config\\settings.json 이 없습니다"))
        upd = app / "config" / "updates.json"
        if upd.is_file():
            txt = upd.read_text(encoding="utf-8", errors="replace").strip()
            if txt and txt != "{}":
                out.append(kv("updates", "업데이트 설정", {"updates.json": txt}, "config\\updates.json"))
        return out


    def sentry(self, app: Path, parts, counts) -> list[dict]:
        d = app / "sentry"
        f = d / "scope_v3.json"
        b_cols = [("time", "시각 (UTC)"), ("category", "분류"), ("event", "이벤트"), ("meaning", "해석"),
                  ("url", "URL / 대상"), ("detail", "세부")]
        if not f.is_file():
            return [table("breadcrumbs", "화면 이동, 요청 기록 (breadcrumb)", b_cols, [],
                          "sentry\\scope_v3.json 이 없습니다 (오류 보고가 꺼져 있으면 생기지 않습니다).")]
        doc = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        out = []

        ev = doc.get("event") or {}
        ctx = ev.get("contexts") or {}
        g = lambda sec, k: (ctx.get(sec) or {}).get(k, "")
        env = {
            "앱 / 버전": f"{g('app', 'app_name')} {g('app', 'app_version')}".strip() or ev.get("release", ""),
            "Electron": g("runtime", "version"), "Chromium": g("chrome", "version"), "Node": g("node", "version"),
            "OS": f"{g('os', 'name')} {g('os', 'version')}".strip(),
            "로케일": g("culture", "locale"), "시간대": g("culture", "timezone"),
            "CPU": g("device", "cpu_description"), "CPU 수": g("device", "processor_count"),
            "메모리 (byte)": g("device", "memory_size"), "화면 해상도": g("device", "screen_resolution"),
            "앱 시작 시각 (UTC)": self._iso(g("app", "app_start_time")),
            "OS 부팅 시각 (UTC)": self._iso(g("device", "boot_time")),
        }
        gpus = [v for k, v in ctx.items() if k.startswith("gpu") and isinstance(v, dict)]
        if gpus:
            env["GPU"] = ", ".join(f"{x.get('name', '')} (vendor {x.get('vendor_id', '')})" for x in gpus)
        if g("app", "app_version"):
            counts["app_version"] = g("app", "app_version")
        sess = d / "session.json"
        if sess.is_file():
            try:
                s = json.loads(sess.read_text(encoding="utf-8", errors="replace"))
                env["Sentry 세션 시작 (UTC)"] = fmt_ms((s.get("started") or 0) * 1000)
                env["Sentry 세션 상태"] = f"{s.get('status', '')} (errors {s.get('errors', '')})"
            except ValueError:
                pass
        out.append(kv("environment", "실행 환경 (sentry)", {k: str(v) for k, v in env.items() if v not in ("", None)},
                      "sentry\\scope_v3.json 의 event.contexts. 분석 대상 PC 의 OS, 로케일, 시간대, 하드웨어(가상 GPU 여부 포함)를 확인합니다."))

        rows = []
        for b in (doc.get("scope") or {}).get("breadcrumbs") or []:
            if not isinstance(b, dict):
                continue
            data = dict(b.get("data")) if isinstance(b.get("data"), dict) else {}
            for k in ("url", "to", "from", "method", "status_code"):
                if k in data and not isinstance(data[k], str):
                    data[k] = json.dumps(data[k], ensure_ascii=False)
            cat = str(b.get("category") or b.get("type") or "")
            msg = str(b.get("message") or "")
            url, meaning, detail = "", "", ""
            if cat == "electron.net" or b.get("type") == "http" or cat == "fetch":
                url = data.get("url", "")
                meaning = f"HTTP {data.get('method', '')} → {data.get('status_code', '')}"
                msg = msg or "http"
            elif cat == "navigation":
                url = data.get("to", "")
                detail = f"from {data.get('from', '')}"
                meaning = "앱 내부 화면 전환"
            elif cat == "console":
                meaning = "알림 권한 허용" if "Granted permissions request for notifications" in msg else "콘솔 로그"
            elif cat.startswith("ui."):
                meaning = "클릭"
            else:
                url = data.get("url", "")
                if url.startswith("http"):
                    meaning = describe_zulip_url(url)
                    if msg == "renderer.context-menu":
                        meaning = f"우클릭 (열려 있던 화면: {meaning or url})"
                    elif msg == "renderer.dom-ready":
                        meaning = f"페이지 로드: {meaning or url}"
                elif msg.startswith("window.") or msg.startswith("app."):
                    meaning = {"window.focus": "창 활성화", "window.blur": "창 비활성화", "window.close": "창 닫기",
                               "window.show": "창 표시", "window.hide": "창 숨김", "window.maximize": "창 최대화",
                               "app.ready": "앱 시작", "app.will-finish-launching": "앱 시작 중"}.get(msg, "")
                rest = {k: v for k, v in data.items() if k not in ("url",)}
                if rest:
                    detail = json.dumps(rest, ensure_ascii=False)
            if cat == "console" and data.get("arguments"):
                detail = json.dumps(data["arguments"], ensure_ascii=False, default=str)
            try:
                ts = fmt_ms(float(b.get("timestamp") or 0) * 1000)
            except (TypeError, ValueError):
                ts = ""
            rows.append({"time": ts, "category": cat, "event": msg,
                         "meaning": meaning, "url": url, "detail": detail,
                         "_rc": "updated" if url.startswith("http") and urlparse(url).fragment else ""})
        rows.sort(key=lambda r: r["time"])
        counts["nav"] = sum(1 for r in rows if r["url"].startswith("http") and urlparse(r["url"]).fragment)
        out.append(table("breadcrumbs", "화면 이동, 요청 기록 (breadcrumb)", b_cols, rows,
                         "sentry\\scope_v3.json 의 breadcrumb (최근 것만 보관). 서버 화면 URL 의 #narrow/channel/<id>-<이름>/topic/<토픽>/with/<메시지id> "
                         "로 사용자가 연 채널, 토픽을 알 수 있습니다 (주황 = 서버 화면 내 위치가 남은 기록). 계정, 메시지 본문은 남지 않습니다.",
                         row_class="_rc"))
        return out

    @staticmethod
    def _iso(s: str) -> str:
        return s.replace("T", " ").replace("Z", "") if s else ""


    def cookies(self, app: Path, parts, counts) -> dict:
        cols = [("partition", "파티션"), ("host", "호스트"), ("name", "이름"), ("meaning", "의미"),
                ("created", "생성 (UTC)"), ("expires", "만료 (UTC)"), ("last_access", "마지막 접근 (UTC)"),
                ("secure", "secure"), ("httponly", "httponly"), ("value", "평문 값"), ("encrypted", "암호문")]
        rows = []
        files = [(p.name, p / "Network" / "Cookies") for p in parts] + [("(루트)", app / "Network" / "Cookies")]
        for pname, f in files:
            if not f.is_file():
                continue
            try:
                con = sqlite3.connect(f"file:{quote(f.as_posix())}?mode=ro&immutable=1", uri=True)
                self._cookie_rows(con, pname, rows)
            except Exception as e:
                rows.append({"partition": pname, "host": "", "name": f"(읽기 실패: {type(e).__name__}: {e})"})
        counts["cookies"] = sum(1 for r in rows if "sessionid" in r["name"])
        return table("cookies", "쿠키", cols, rows,
                     "Partitions\\webviewsession\\Network\\Cookies. Zulip Desktop 은 쿠키를 OS 암호화 없이 value 컬럼에 평문으로 저장합니다. "
                     "__Host-sessionid 는 서버 DB 의 django_session 과 대조할 수 있고, 세션 쿠키가 살아 있으면 계정 접근이 가능하므로 취급에 주의하세요.")

    @staticmethod
    def _cookie_rows(con, pname: str, rows: list):
        try:
            con.row_factory = sqlite3.Row
            for r in con.execute("SELECT * FROM cookies ORDER BY creation_utc"):
                r = dict(r)
                enc = r.get("encrypted_value") or b""
                name = r.get("name", "")
                rows.append({
                    "partition": pname, "host": r.get("host_key", ""), "name": name,
                    "meaning": {"__Host-sessionid": "로그인 세션 (서버 django_session.session_key)",
                                "sessionid": "로그인 세션 (서버 django_session.session_key)",
                                "__Host-csrftoken": "CSRF 토큰", "csrftoken": "CSRF 토큰"}.get(name, ""),
                    "created": fmt_webkit(r.get("creation_utc")), "expires": fmt_webkit(r.get("expires_utc")),
                    "last_access": fmt_webkit(r.get("last_access_utc")),
                    "secure": r.get("is_secure", ""), "httponly": r.get("is_httponly", ""),
                    "value": r.get("value", ""),
                    "encrypted": f"{len(enc)} bytes (접두어 {enc[:3].decode('latin1')!r})" if enc else "",
                })
        finally:
            con.close()


    def local_storage(self, app: Path, parts, counts) -> list[dict]:
        cols = [("partition", "파티션"), ("seq", "seq"), ("state", "상태"), ("time", "기록 시각 (UTC)"),
                ("origin", "origin"), ("key", "키"), ("meaning", "의미"), ("value", "값")]
        d_cols = [("time", "기록 시각 (UTC)"), ("state", "상태"), ("kind", "종류"), ("to", "대상 (채널, 토픽 / DM)"),
                  ("content", "내용"), ("updated", "수정 시각 (UTC)"), ("draft_id", "초안 id"), ("seq", "seq")]
        rows, drafts, versions = [], [], 0
        dirs = [(p.name, p / "Local Storage" / "leveldb") for p in parts] + [("(루트)", app / "Local Storage" / "leveldb")]
        latest_draft_seq: dict = {}
        for pname, d in dirs:
            if not d.is_dir():
                continue
            db = ccl_chromium_localstorage.LocalStoreDb(d)
            try:
                recs = sorted(db.iter_all_records(include_deletions=True), key=lambda r: r.leveldb_seq_number)
                for r in recs:
                    batch = db.find_batch(r.leveldb_seq_number)
                    t = fmt_dt(batch.timestamp) if batch else ""
                    key = r.script_key or ""
                    m = re.match(r"^ls__(\d+)__(.+)$", key)
                    short = m[2] if m else key
                    rows.append({"partition": pname, "seq": r.leveldb_seq_number,
                                 "state": "live" if r.is_live else "deleted", "time": t, "origin": r.storage_key,
                                 "key": key, "meaning": LS_MEANING.get(short, ""),
                                 "value": r.value if r.value is not None else ""})
                    if short == "drafts" and r.value:
                        versions += 1
                        try:
                            obj = json.loads(r.value)
                        except ValueError:
                            continue
                        data = obj.get("data") if isinstance(obj, dict) else None
                        if not isinstance(data, dict):
                            continue
                        k = (pname, r.storage_key)
                        if r.is_live:
                            latest_draft_seq[k] = max(latest_draft_seq.get(k, -1), r.leveldb_seq_number)
                        for did, dv in data.items():
                            if not isinstance(dv, dict):
                                continue
                            drafts.append({"time": t, "_seq": r.leveldb_seq_number, "_k": k, "seq": r.leveldb_seq_number,
                                           **self._draft_row(did, dv)})
            finally:
                db.close()
        for x in drafts:
            cur = x["_seq"] == latest_draft_seq.get(x.pop("_k"))
            x["state"] = "현재 값" if cur else "이전 기록"
            x["_rc"] = "" if cur else "updated"
            del x["_seq"]
        counts["drafts"] = sum(1 for x in drafts if x["state"] == "현재 값")
        rows.sort(key=lambda r: (r["partition"], r["seq"]))
        desc = (f"ls__1__drafts 기록 {versions}건에서 찾은 초안입니다. 초안을 저장, 전송할 때마다 전체 목록이 새 레코드로 쌓여 "
                "지금은 지워진(전송, 삭제된) 초안도 '이전 기록'으로 복원됩니다.")
        if versions and not drafts:
            desc = f"ls__1__drafts 기록 {versions}건이 모두 빈 객체({{}})입니다. 미전송 초안이 없었습니다."
        return [
            table("drafts", "미전송 초안", d_cols, drafts, desc, row_class="_rc"),
            table("localstorage", "Local Storage", cols, rows,
                  "Partitions\\webviewsession\\Local Storage\\leveldb (서버 웹 UI 상태). 키는 ls__<형식 버전>__<이름>. "
                  "같은 키의 이전 값, 삭제 기록도 seq 순으로 남습니다.", row_class="state"),
        ]

    @staticmethod
    def _draft_row(did: str, dv: dict) -> dict:
        kind = dv.get("type", "")
        if kind == "stream":
            to = f"채널 id {dv.get('stream_id', '')} / 토픽 '{dv.get('topic', '')}'"
        else:
            rid = dv.get("private_message_recipient_ids") or dv.get("private_message_recipient") or ""
            to = f"DM {json.dumps(rid, ensure_ascii=False) if isinstance(rid, list) else rid}"
        return {"kind": {"stream": "채널", "private": "DM"}.get(kind, kind), "to": to,
                "content": dv.get("content", ""), "updated": fmt_ms(dv.get("updatedAt")), "draft_id": did}


    @staticmethod
    def _cache_kind(url: str) -> str:
        p = urlparse(url).path if url.startswith("http") else url
        if "/user_uploads/thumbnail/" in p:
            return "첨부 썸네일"
        if "/user_uploads/" in p:
            return "첨부 파일"
        if "/user_avatars/" in p:
            return "사용자 아바타"
        if p.startswith("/api/") or p.startswith("/json/"):
            return "API 응답"
        if p.startswith("/static/"):
            return "정적 자원"
        return "외부" if url.startswith("http") else ""

    def cache(self, app: Path, parts, counts) -> list[dict]:
        e_cols = [("time", "캐시 시각 (UTC)"), ("kind", "분류"), ("url", "URL"), ("ctype", "Content-Type"),
                  ("encoding", "인코딩"), ("size", "크기(byte)"), ("server_date", "서버 응답 시각 (Date)"),
                  ("last_modified", "Last-Modified"), ("location", "저장 위치"), ("note", "비고")]
        d = chromium_cache.find_cache_dir(app)
        if d is None:
            return [table("cache_entries", "캐시 엔트리", e_cols, [], "Partitions\\webviewsession\\Cache\\Cache_Data 가 없습니다.")]
        entries, settings = self._scan_cache(d, e_cols)
        out = []
        if settings:
            am = settings.get("authentication_methods") or {}
            out.append(kv("server_settings", "서버 정보 (캐시된 server_settings)", {
                "조직 이름 (realm_name)": settings.get("realm_name", ""),
                "조직 URL (realm_url)": settings.get("realm_url") or settings.get("realm_uri", ""),
                "서버 버전 (zulip_version)": settings.get("zulip_version", ""),
                "merge base": settings.get("zulip_merge_base", ""),
                "기능 레벨": settings.get("zulip_feature_level", ""),
                "사용 가능한 인증 방식": ", ".join(k for k, v in am.items() if v),
                "이메일 형식 사용자명 필수": settings.get("require_email_format_usernames", ""),
                "푸시 알림": settings.get("push_notifications_enabled", ""),
                "웹 공개 접근": settings.get("realm_web_public_access_enabled", ""),
                "조직 설명": settings.get("realm_description", ""),
                "조직 아이콘": settings.get("realm_icon", ""),
                "응답 받은 시각 (UTC)": settings.get("_cached", ""),
            }, "캐시의 /api/v1/server_settings 응답 (로그인 전에 앱이 서버를 확인할 때 받음). 조직 이름 설명은 서버가 준 HTML 을 텍스트로 보여 줍니다."))
        counts["cache_entries"] = len(entries)
        rel = d.relative_to(app).as_posix() if d.is_relative_to(app) else d.name
        out.append(table("cache_entries", "캐시 엔트리", e_cols, entries,
                         f"{rel} (Chromium 블록파일 캐시). 정적 자원 외에 사용자 아바타(/user_avatars/<조직id>/<해시>), "
                         "첨부 썸네일(/user_uploads/thumbnail/…), API 응답이 남습니다. 아바타 경로는 서버 uploads/avatars 와 같습니다. "
                         "행을 누르면 본문을 볼 수 있습니다."))
        root_cache = app / "Cache" / "Cache_Data"
        if root_cache.is_dir() and root_cache.resolve() != d.resolve() and (root_cache / "index").is_file():
            r_entries, _ = self._scan_cache(root_cache, e_cols)
            out.append(table("app_cache", "앱 자체 캐시 (루트)", [c for c in e_cols if c[0] != "kind"], r_entries,
                             "Zulip\\Cache\\Cache_Data. 서버 화면이 아니라 앱 자체가 받은 응답(맞춤법 사전 다운로드 등)입니다. 목록만 표시합니다."))
        return out

    def _scan_cache(self, d: Path, e_cols) -> tuple[list[dict], dict]:
        cache = ccl_chromium_cache.ChromiumBlockFileCache(d)
        entries, settings = [], {}
        try:
            for key in cache.keys():
                es = cache._keys[key]
                url = chromium_cache.url_of(key)
                row = {"time": fmt_dt(es.creation_time) if es.creation_time and es.creation_time.year > 1601 else "",
                       "kind": self._cache_kind(url), "url": url, "ctype": "", "encoding": "", "size": "",
                       "server_date": "", "last_modified": "", "location": "", "note": "", "_key": key}
                try:
                    md = (cache.get_metadata(key) or [None])[0]
                    if md:
                        row["ctype"] = ", ".join(md.get_attribute("content-type"))
                        row["encoding"] = ", ".join(md.get_attribute("content-encoding"))
                        row["server_date"] = ", ".join(md.get_attribute("date"))
                        row["last_modified"] = ", ".join(md.get_attribute("last-modified"))
                    loc = (cache.get_location_for_cachefile(key) or [None])[0]
                    if loc:
                        row["location"] = f"{loc.file_name} @ {loc.offset}"
                    data = (cache.get_cachefile(key) or [None])[0]
                    if data is not None:
                        row["size"] = len(data)
                        if "/api/v1/server_settings" in url and "json" in row["ctype"]:
                            body, note = chromium_cache.decode_body(data, row["encoding"])
                            row["note"] = note
                            try:
                                settings = json.loads(body.decode("utf-8", "replace"))
                                settings["_cached"] = row["time"]
                            except ValueError:
                                pass
                    elif not url:
                        row["note"] = "키 없음 (빈/손상 엔트리)"
                    else:
                        row["note"] = "본문 없음 (헤더만)"
                    if key.startswith("Range_"):
                        row["note"] = (row["note"] + ", " if row["note"] else "") + "부분 응답(Range)"
                except Exception as e:
                    row["note"] = f"읽기 실패: {type(e).__name__}: {e}"
                entries.append(row)
        finally:
            for _, f in cache._block_files.values():
                f.close()
        entries.sort(key=lambda r: r["time"] or "~")
        return entries, settings


    def app_logs(self, app: Path, parts, counts) -> dict:
        cols = [("time", "시각 (로컬)"), ("file", "파일"), ("level", "수준"), ("message", "내용")]
        d = app / "Logs"
        if not d.is_dir():
            d = app / "logs"
        rows = []
        pat = re.compile(r"^\[(?P<t>[\d\- :.]+)\]\s+\[(?P<lv>\w+)\]\s*(?P<msg>.*)$")
        empty = []
        for f in sorted(d.glob("*.log")) if d.is_dir() else []:
            text = f.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                empty.append(f.name)
                continue
            for line in text.splitlines():
                m = pat.match(line)
                if m:
                    rows.append({"time": m["t"], "file": f.name, "level": m["lv"], "message": m["msg"]})
                elif rows and line.strip():
                    rows[-1]["message"] += "\n" + line
        rows.sort(key=lambda r: r["time"])
        desc = "Logs\\*.log. 시각은 PC 로컬 시간입니다 (sentry 의 시간대 참고). 업데이트 확인 시각으로 앱 실행 시점을 알 수 있습니다."
        if empty:
            desc += f" 빈 파일: {', '.join(empty)}."
        return table("app_log", "앱 로그", cols, rows, desc)


    FINDINGS_DESC = (
        "이 PC 의 앱 데이터에 남은 삭제, 편집 정황만 모았습니다. 확실 = 기록으로 확인되는 사실, 추정 = 정황. "
        "점검 항목: Local Storage 에서 지워진 키(앱이 쓰고 바로 지우는 임시 키 제외). "
        "서버 기록과의 대조는 좌측 '교차 분석'에서 봅니다 (Server 증거도 올린 경우)."
    )

    LS_ROUTINE = ("tusSupport",)

    def findings(self, sections: list[dict]) -> list[dict]:
        S = {s["id"]: s for s in sections if s.get("type") == "table"}
        rows_of = lambda sid: S[sid]["rows"] if sid in S else []
        out, seen = [], set()
        for r in rows_of("localstorage"):
            k = (r.get("partition"), r.get("origin"), r.get("key"), r.get("seq"))
            if r.get("state") != "deleted" or r.get("key") in self.LS_ROUTINE or "임시 키" in (r.get("meaning") or "") or k in seen:
                continue
            seen.add(k)
            out.append(finding(CERTAIN, "앱 저장소 키 삭제", r.get("time"), f"{r.get('origin')}, {r.get('key')}",
                               f"Local Storage 에서 지워진 키입니다 (seq {r.get('seq')}). {r.get('meaning') or ''}".strip(),
                               "Local Storage", {"section": "localstorage", "match": {"seq": r.get("seq"), "key": r.get("key")}}, "deleted"))
        return out

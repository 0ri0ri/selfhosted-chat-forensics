from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from ...mongoaccess import date_str, find_dbpath, iso_str, oid, text
from ...vendor.mongodb_viewer.engine.mongo import open_dbpath
from ...vendor.mongodb_viewer.engine.mongo.bsonlib import Binary, Date
from ..base import CERTAIN, INFERRED, BaseParser, error_section, finding, fmt_ms, kv, parse_utc, short, table

SOURCE = {"file": "현재 파일", "hs": "히스토리 스토어", "stale": "끊긴 블록", "oplog": "oplog 재구성", "trash": "휴지통(__trash)"}
STATE = {"live": "live", "deleted": "삭제", "updated": "이전 버전", "unknown": "판단 불가"}
ROOM_TYPE = {"c": "공개 채널", "p": "비공개 그룹", "d": "DM", "l": "옴니채널", "v": "보이스"}
SESSION_TYPE = {"session": "session (원본 세션)", "computed-session": "computed-session (계산된 세션)",
                "user_daily": "user_daily (사용자 일별 집계)"}

MSG_TYPE = {
    "": "일반", "e2e": "E2E 암호화", "uj": "방 참여", "ul": "방 나감", "ult": "팀 나감", "ujt": "팀 참여",
    "au": "사용자 추가", "ru": "사용자 제거", "r": "방 이름 변경", "rm": "메시지 삭제 표시",
    "room_changed_topic": "주제 변경", "room_changed_description": "설명 변경",
    "room_changed_announcement": "공지 변경", "room_changed_privacy": "공개 범위 변경", "room_changed_avatar": "방 아바타 변경",
    "room_e2e_enabled": "E2E 켜짐", "room_e2e_disabled": "E2E 꺼짐", "message_pinned": "메시지 고정",
    "message_pinned_e2e": "E2E 메시지 고정", "discussion-created": "토론 생성", "user-muted": "음소거",
    "user-unmuted": "음소거 해제", "subscription-role-added": "방 역할 부여", "subscription-role-removed": "방 역할 해제",
    "videoconf": "화상회의", "jitsi_call_started": "화상회의 시작", "added-user-to-team": "팀에 사용자 추가",
    "removed-user-from-team": "팀에서 사용자 제거", "user-converted-to-team": "팀으로 전환",
}

KEY_SETTINGS = [
    "Site_Url", "Site_Name", "uniqueID", "Organization_Name", "Organization_Email", "Server_Type", "Language",
    "FileUpload_Storage_Type", "FileUpload_FileSystemPath", "FileUpload_MaxFileSize", "FileUpload_Enabled",
    "E2E_Enable", "E2E_Enable_Encrypt_Files", "E2E_Enabled_Default_DirectRooms", "E2E_Enabled_Default_PrivateRooms",
    "Message_AllowDeleting", "Message_AllowDeleting_BlockDeleteInMinutes", "Message_AllowEditing", "Message_KeepHistory",
    "Message_ShowDeletedStatus", "RetentionPolicy_Enabled", "RetentionPolicy_MaxAge_Channels", "RetentionPolicy_MaxAge_Groups",
    "RetentionPolicy_MaxAge_DMs", "Accounts_TwoFactorAuthentication_Enabled", "Accounts_RegistrationForm",
    "Accounts_AllowAnonymousRead", "Show_Setup_Wizard", "Cloud_Workspace_Id", "Cloud_Workspace_Name",
    "Log_Level", "Log_View_Limit", "Troubleshoot_Disable_Data_Exporter_Processor",
]
SECRET_RE = re.compile(r"(pass|secret|token|private|_key$|apikey|api_key|credential)", re.I)


def mask(v: str) -> str:
    v = str(v)
    return "****" if len(v) <= 4 else v[:4] + "…" + f" ({len(v)}자)"


URL_CRED_RE = re.compile(r"(://[^/\s:@]+:)([^@\s/]+)@")


def mask_env(k: str, v: str) -> str:
    if SECRET_RE.search(k) and v:
        return mask(v)
    return URL_CRED_RE.sub(lambda m: m[1] + "****@", str(v))


def clip(s, n=300):
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n] + "…"


def jdump(v) -> str:
    return json.dumps(v, ensure_ascii=False, default=str)


class RocketChatServerParser(BaseParser):
    mode = "server"
    app = "rocketchat"
    is_dummy = False

    def parse(self, root: Path, inventory: list[dict]) -> dict:
        sections: list[dict] = []
        counts: dict = {}
        extra: dict = {}
        try:
            secs, extra = self.mongodb(root, counts)
            sections.extend(secs)
        except Exception as e:
            sections.append(error_section("mongodb", "MongoDB", e))
        for fn, title in [(self.compose, "rocketchat-compose 설정"), (self.containers, "Docker 컨테이너"),
                          (self.bash_history, "셸 명령 기록")]:
            try:
                sections.extend(fn(root, counts))
            except Exception as e:
                sections.append(error_section(fn.__name__, title, e))

        summary = [
            {"label": "서버 버전", "value": counts.get("version") or "-"},
            {"label": "사용자", "value": counts.get("users", 0)},
            {"label": "방", "value": counts.get("rooms", 0)},
            {"label": "메시지 (live)", "value": counts.get("messages", 0)},
            {"label": "삭제, 이전 버전 메시지", "value": counts.get("messages_old", 0)},
            {"label": "첨부 (GridFS)", "value": counts.get("files", 0)},
            {"label": "로그인 이벤트", "value": counts.get("logins", 0)},
        ]
        return {"summary": summary, "sections": sections, **extra}


    def compose(self, root: Path, counts) -> list[dict]:
        out = []
        envs = sorted((p for p in root.rglob(".env") if p.is_file()), key=lambda p: len(p.parts))
        compose_files = sorted(p for p in root.rglob("compose*.y*ml") if p.is_file())
        compose_files += sorted(p for p in root.rglob("docker-compose*.y*ml") if p.is_file())
        for env in envs:
            items = {}
            for line in env.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                k, v = s.split("=", 1)
                k, v = k.strip(), v.strip().strip('"').strip("'")
                items[k] = mask_env(k, v)
                if k == "RELEASE" and v:
                    counts.setdefault("version", v)
            out.append(kv(f"env_{len(out)}", f"compose 환경 변수 ({env.parent.name}/.env)", items,
                          f"{env.relative_to(root).as_posix()}. RELEASE = Rocket.Chat 버전, ROOT_URL = 외부 접속 주소, "
                          "BIND_IP, HOST_PORT = 바인드 주소. 비밀번호, 토큰류 값은 앞 4자만 표시합니다 (원문은 파일 목록)."))
        if compose_files:
            rows = []
            for f in compose_files:
                txt = f.read_text(encoding="utf-8", errors="replace")
                service = ""
                for line in txt.splitlines():
                    m = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
                    if m:
                        service = m[1]
                    m = re.match(r"^\s+image:\s*(.+)$", line)
                    if m:
                        rows.append({"file": f.relative_to(root).as_posix(), "service": service, "image": m[1].strip()})
            out.append(table("compose_images", "compose 서비스, 이미지", [("file", "파일"), ("service", "서비스"), ("image", "이미지 (변수 포함)")],
                             rows, "compose*.yml 의 서비스별 image. ${RELEASE} 같은 변수는 .env 값으로 바뀝니다."))
        return out

    def containers(self, root: Path, counts) -> list[dict]:
        cfgs = sorted(p for p in root.rglob("config.v2.json") if p.is_file() and p.parent.parent.name == "containers")
        if not cfgs:
            return []
        rows, logs, log_notes = [], [], []
        for cfg in cfgs:
            try:
                d = json.loads(cfg.read_text(encoding="utf-8", errors="replace"))
            except ValueError as e:
                rows.append({"id": cfg.parent.name[:12], "name": f"(해석 실패: {e})"})
                continue
            if not isinstance(d, dict):
                rows.append({"id": cfg.parent.name[:12], "name": "(config.v2.json 이 객체가 아님)"})
                continue
            c = d.get("Config") if isinstance(d.get("Config"), dict) else {}
            st = d.get("State") if isinstance(d.get("State"), dict) else {}
            env = []
            for e in c.get("Env") or []:
                k, _, v = str(e).partition("=")
                env.append(f"{k}={mask_env(k, v)}")
            mounts = [f"{m.get('Source') or m.get('Name', '')} → {m.get('Destination', '')}"
                      for m in (d.get("MountPoints") or {}).values() if isinstance(m, dict)]
            nets = (d.get("NetworkSettings") or {}).get("Networks") or {}
            name = (d.get("Name") or "").lstrip("/")
            rows.append({"name": name, "image": c.get("Image", ""), "id": cfg.parent.name[:12],
                         "created": self._dock_t(d.get("Created")), "started": self._dock_t(st.get("StartedAt")),
                         "finished": self._dock_t(st.get("FinishedAt")), "running": str(st.get("Running", "")),
                         "ip": ", ".join(f"{k}: {v.get('IPAddress', '')}" for k, v in nets.items() if isinstance(v, dict)),
                         "mounts": "\n".join(mounts), "env": "\n".join(env)})
            if "rocketchat" in name.lower() or "rocket.chat" in c.get("Image", "").lower():
                for e in c.get("Env") or []:
                    k, _, v = str(e).partition("=")
                    if k in ("RELEASE", "VERSION") and v:
                        counts.setdefault("version", v)
            for lf in sorted(cfg.parent.glob("*-json.log*")):
                n_all, n_kept = self._docker_log(lf, name, logs)
                if n_all != n_kept:
                    log_notes.append(f"{name}: {n_all:,}줄 중 {n_kept:,}줄")
        logs.sort(key=lambda r: r["time"])
        desc = ("/var/lib/docker/containers/<ID>/<ID>-json.log (한 줄 = {log, stream, time}, 시각 UTC). "
                "rocketchat 컨테이너의 서버 시작 배너, 메일 오류, 라이선스 기록, caddy 의 인증서, 프록시 오류 등이 남습니다.")
        if log_notes:
            desc += (" mongod 구조화 로그는 접속, 인증 같은 반복 줄을 빼고 경고, 오류와 시작, 저장소, 복제 관련 줄만, 파일당 최대 "
                     f"{self.LOG_CAP:,}줄만 보입니다 (" + "; ".join(log_notes) + "). 전체는 파일 목록의 원본에서 확인하세요.")
        return [
            table("containers", "Docker 컨테이너", [
                ("name", "이름"), ("image", "이미지"), ("id", "ID"), ("created", "생성 (UTC)"), ("started", "시작 (UTC)"),
                ("finished", "종료 (UTC)"), ("running", "Running"), ("ip", "네트워크 IP"), ("mounts", "마운트"), ("env", "환경 변수")],
                rows, "/var/lib/docker/containers/<ID>/config.v2.json. Running=true, 종료 시각 0001-01-01 이면 정상 정지 없이 전원이 꺼진 것입니다. "
                "환경 변수의 ROOT_URL, MONGO_URL 로 서비스 주소와 DB 연결을 확인합니다. 비밀값은 앞 4자만 표시합니다."),
            table("container_logs", "컨테이너 로그", [("time", "시각 (UTC)"), ("container", "컨테이너"), ("stream", "stream"),
                                                  ("message", "내용")], logs, desc),
        ]

    @staticmethod
    def _dock_t(s) -> str:
        if not s or not isinstance(s, str) or s.startswith("0001-01-01"):
            return "" if not s else "0001-01-01 (기록 없음)"
        m = re.match(r"^(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)(\.\d+)?", s)
        if not m:
            return s
        frac = (m[3] or ".000")[1:4].ljust(3, "0")
        return f"{m[1]} {m[2]}.{frac}"

    MONGO_KEEP = ("CONTROL", "STORAGE", "REPL", "RECOVERY", "ELECTION", "SHARDING", "INDEX", "COMMAND")

    LOG_CAP = 5000

    def _docker_log(self, lf: Path, name: str, out: list) -> tuple[int, int]:
        n_all = n_kept = 0
        with open(lf, "rb") as f:
            for raw in f:
                raw = raw.rstrip(b"\r\n").rstrip(b"\0")
                if not raw.strip():
                    continue
                n_all += 1
                try:
                    d = json.loads(raw.decode("utf-8", "replace"))
                except ValueError:
                    continue
                if not isinstance(d, dict):
                    continue
                msg = str(d.get("log", "")).rstrip("\n")
                if msg.startswith("{") and '"c"' in msg and '"s"' in msg:
                    try:
                        j = json.loads(msg)
                    except ValueError:
                        j = None
                    if isinstance(j, dict) and "c" in j and "s" in j:
                        if j.get("s") not in ("W", "E", "F") and j.get("c") not in self.MONGO_KEEP:
                            continue
                        msg = f"[{j.get('s', '')}] {j.get('c', '')}: {j.get('msg', '')} {jdump(j.get('attr'))[:400] if j.get('attr') else ''}"
                if n_kept >= self.LOG_CAP:
                    continue
                n_kept += 1
                out.append({"time": self._dock_t(d.get("time")), "container": name, "stream": d.get("stream", ""),
                            "message": clip(msg, 2000)})
        return n_all, n_kept

    def bash_history(self, root: Path, counts) -> list[dict]:
        files = sorted(p for p in root.rglob(".bash_history") if p.is_file())
        rows = []
        for f in files:
            ts = ""
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                m = re.match(r"^#(\d{9,11})$", line)
                if m:
                    ts = fmt_ms(int(m[1]) * 1000)
                    continue
                if line.strip():
                    rows.append({"file": f.relative_to(root).as_posix(), "line": i, "time": ts, "command": line,
                                 "_rc": "updated" if re.search(r"rocket|docker|compose|mongo|caddy|\.env", line, re.I) else ""})
                    ts = ""
        if not files:
            return []
        return [table("bash_history", "셸 명령 기록 (.bash_history)", [("file", "파일"), ("line", "줄"), ("time", "시각 (UTC, HISTTIMEFORMAT 시)"),
                                                                    ("command", "명령")], rows,
                      "사용자 홈의 .bash_history. 시각은 HISTTIMEFORMAT 이 설정된 경우(#<epoch> 줄)에만 남습니다. "
                      "주황 = Rocket.Chat, Docker, MongoDB 관련 명령 (.env 에 BIND_IP, HOST_PORT 를 덧붙인 명령 등).", row_class="_rc")]


    def mongodb(self, root: Path, counts) -> tuple[list[dict], dict]:
        cands = find_dbpath(root)
        if not cands:
            return [kv("mongodb", "MongoDB", {"상태": "MongoDB 데이터 디렉터리(WiredTiger.turtle + WiredTiger.wt)를 찾지 못했습니다."},
                       "수집 가이드의 /var/lib/docker/volumes/<프로젝트>_mongodb_data/_data/ (또는 /var/lib/mongodb) 를 폴더째 넣어 주세요.")], {}
        chosen = None
        for c in cands[:10]:
            try:
                db = open_dbpath(c)
            except Exception:
                continue
            if any(ns.endswith(".rocketchat_message") for ns in db.catalog):
                if chosen:
                    chosen[1].close()
                chosen = (c, db)
                break
            if chosen is None:
                chosen = (c, db)
            else:
                db.close()
        if chosen is None:
            db = open_dbpath(cands[0])
            chosen = (cands[0], db)
        dbpath, db = chosen
        try:
            return self._mongo_sections(root, dbpath, db, [dbpath] + [c for c in cands if c != dbpath], counts)
        finally:
            db.close()

    def _mongo_sections(self, root, dbpath, db, cands, counts):
        out: list[dict] = []
        names = [ns.split(".", 1)[0] for ns in db.catalog if ns.endswith(".rocketchat_message")]
        dbn = "rocketchat" if "rocketchat" in names else (names[0] if names else "rocketchat")
        ns = lambda c: f"{dbn}.{c}"
        has = lambda c: ns(c) in db.catalog
        rel = dbpath.relative_to(root).as_posix() if dbpath != root else "."
        extra = {"mongo": {"dbpath": rel, "db": dbn}}

        def rows_of(c):
            return db.rows(ns(c)) if has(c) else []

        def guard(fn, sid, title):
            try:
                r = fn()
                out.extend(r if isinstance(r, list) else [r])
            except Exception as e:
                out.append(error_section(sid, title, e))

        users, rooms = {}, {}
        for r in rows_of("users"):
            d = r.get("doc")
            if isinstance(d, dict) and "_id" in d and (oid(d["_id"]) not in users or r["state"] == "live"):
                users[oid(d["_id"])] = d
        for r in rows_of("rocketchat_room"):
            d = r.get("doc")
            if isinstance(d, dict) and "_id" in d and (oid(d["_id"]) not in rooms or r["state"] == "live"):
                rooms[oid(d["_id"])] = d

        def uname(uid):
            u = users.get(oid(uid))
            return u.get("username", "") if u else oid(uid)

        def rname(rid):
            r = rooms.get(oid(rid))
            if not r:
                return oid(rid)
            if r.get("t") == "d":
                un = r.get("usernames")
                return "DM: " + ", ".join(map(str, un)) if isinstance(un, list) and un else f"DM {oid(rid)}"
            return r.get("fname") or r.get("name") or oid(rid)

        guard(lambda: self._db_info(db, dbn, rel, cands, root, counts), "mongo_info", "MongoDB 정보")
        guard(lambda: self._settings(rows_of("rocketchat_settings"), rows_of("rocketchat_statistics"), rows_of("migrations"), counts),
              "settings", "서버 설정")
        guard(lambda: self._users(rows_of("users"), counts), "users", "사용자")
        guard(lambda: self._rooms(rows_of("rocketchat_room"), uname, counts), "rooms", "방")
        guard(lambda: self._subscriptions(rows_of("rocketchat_subscription"), rname), "subscriptions", "방 참여 (구독)")
        guard(lambda: self._messages(rows_of("rocketchat_message"), rows_of("rocketchat__trash"), uname, rname, counts),
              "messages", "메시지")
        guard(lambda: self._trash(rows_of("rocketchat__trash"), rname), "trash", "휴지통")
        guard(lambda: self._uploads(db, dbn, rows_of("rocketchat_uploads"), uname, rname, counts), "uploads", "첨부 파일")
        guard(lambda: self._events(rows_of("rocketchat_server_events"), uname, counts), "server_events", "서버 이벤트")
        guard(lambda: self._sessions(rows_of("rocketchat_sessions"), uname), "sessions", "세션")
        guard(lambda: self._oplog(db, dbn), "oplog", "oplog")
        order = ["messages", "uploads", "trash", "users", "rooms", "subscriptions", "server_events", "sessions",
                 "settings", "settings_changed", "mongo_info", "oplog"]
        out.sort(key=lambda x: order.index(x["id"]) if x["id"] in order else len(order))
        return out, extra

    def _db_info(self, db, dbn, rel, cands, root, counts):
        info = db.info()
        op = db.oplog_summary()
        dbs = db.databases()
        items = {
            "dbPath (ZIP 안)": rel,
            "WiredTiger 버전": info.get("wiredtiger_version") or "",
            "데이터베이스": ", ".join(f"{d['name']} ({d['collections']}개 컬렉션)" for d in dbs),
            "Rocket.Chat DB": dbn,
            "파일 수": f"{info.get('files', 0):,} (컬렉션 {info['file_kinds'].get('collection', 0)}, 인덱스 {info['file_kinds'].get('index', 0)}, "
                      f"저널 {info['file_kinds'].get('journal', 0)})",
            "블록 압축": ", ".join(f"{k} {v}" for k, v in (info.get("compressors") or {}).items()),
            "마지막 체크포인트 (UTC)": iso_str((info.get("metadata_checkpoint") or {}).get("time_iso")),
            "mongod.lock 크기": "" if info.get("mongod_lock_size") is None else f"{info['mongod_lock_size']} (0 이 아니면 정상 종료 안 됨)",
            "oplog": (f"{op.get('entries', 0):,}건, {iso_str(op.get('first_wall'))} ~ {iso_str(op.get('last_wall'))} (UTC)"
                      if op.get("entries") else ("레플리카셋 아님 (oplog 없음)" if not op.get("available") else "비어 있음")),
        }
        if len(cands) > 1:
            items["다른 dbPath"] = ", ".join(p.relative_to(root).as_posix() for p in cands[1:]) + " (분석하지 않음 - [DB 원본 보기] 대상도 위 dbPath)"
        return kv("mongo_info", "MongoDB 정보", items,
                  "MongoDB Viewer 엔진으로 dbPath 를 직접 읽었습니다 (mongod 미실행, 원본 읽기 전용). 마지막 체크포인트 이후 저널에만 있는 쓰기는 보이지 않습니다. "
                  "모든 컬렉션은 제목 옆 [DB 원본 보기] 에서 삭제, 이전 버전과 함께 볼 수 있습니다.")

    def _settings(self, srows, strows, migrows, counts):
        live = {}
        for r in srows:
            d = r.get("doc")
            if isinstance(d, dict) and r["state"] == "live":
                live[oid(d.get("_id"))] = d
        stats = [r["doc"] for r in strows if isinstance(r.get("doc"), dict) and r["state"] == "live"]
        stats.sort(key=lambda d: date_str(d.get("createdAt")))
        st = stats[-1] if stats else {}
        if st.get("version"):
            counts["version"] = st["version"]
        items = {}
        if st:
            items["버전 (rocketchat_statistics.version)"] = st.get("version", "")
            items["통계 생성 (UTC)"] = date_str(st.get("createdAt"))
            items["설치 시각 (installedAt)"] = text(st.get("installedAt")) or ""
            items["OS"] = text(st.get("os"), 300) or ""
            items["MongoDB 버전"] = st.get("mongoVersion", "")
        for d in (r["doc"] for r in migrows if isinstance(r.get("doc"), dict) and r["state"] == "live"):
            if d.get("_id") == "control":
                items["마이그레이션 버전 (migrations.control)"] = text(d.get("version"))
        for k in KEY_SETTINGS:
            if k in live:
                v = live[k].get("value")
                items[k] = mask(text(v)) if SECRET_RE.search(k) and v else text(v, 500)
        rows = []
        for k, d in sorted(live.items()):
            v, pv = d.get("value"), d.get("packageValue")
            if "packageValue" in d and text(v) == text(pv):
                continue
            secret = d.get("type") == "password" or SECRET_RE.search(k)
            rows.append({"key": k, "value": mask(text(v)) if secret and v not in (None, "") else text(v, 500),
                         "default": text(pv, 200), "type": d.get("type", ""), "updated": date_str(d.get("_updatedAt")),
                         "group": d.get("group", "")})
        rows.sort(key=lambda r: r["updated"] or "", reverse=True)
        return [kv("settings", "서버 정보, 주요 설정", items,
                   "rocketchat_settings(현재 값), rocketchat_statistics(최근 통계). FileUpload_Storage_Type 이 GridFS 면 첨부는 MongoDB 안에, "
                   "FileSystem 이면 FileUpload_FileSystemPath 디렉터리에 있습니다."),
                table("settings_changed", "기본값과 다른 설정", [("key", "설정"), ("value", "현재 값"), ("default", "기본값 (packageValue)"),
                                                          ("type", "유형"), ("group", "그룹"), ("updated", "수정 (UTC)")], rows,
                      "관리자가 바꾼 설정입니다. 비밀번호 유형 값은 앞 4자만 표시합니다. 바꾼 사람, IP 는 '서버 이벤트'의 settings.changed 에 남습니다.")]

    def _users(self, urows, counts):
        rows = []
        def hashes(d):
            sv = (d.get("services") or {}) if isinstance(d, dict) else {}
            return [{"hash": str(t.get("hashedToken")), "when": date_str(t.get("when"))}
                    for t in ((sv.get("resume") or {}).get("loginTokens")) or [] if isinstance(t, dict) and t.get("hashedToken")]
        old_tokens: dict[str, dict[str, dict]] = {}
        for r in urows:
            d = r.get("doc")
            if isinstance(d, dict) and r["state"] == "updated":
                for t in hashes(d):
                    old_tokens.setdefault(oid(d.get("_id")), {})[t["hash"]] = t
        for r in urows:
            d = r.get("doc")
            if not isinstance(d, dict) or r["state"] == "updated":
                continue
            sv = d.get("services") or {}
            toks = ((sv.get("resume") or {}).get("loginTokens")) or []
            whens = sorted(date_str(t.get("when")) for t in toks if isinstance(t, dict))
            e2e = d.get("e2e") or {}
            rows.append({
                "state": STATE.get(r["state"], r["state"]), "_rc": r["state"] if r["state"] != "live" else "",
                "id": oid(d.get("_id")), "username": d.get("username", ""), "name": d.get("name", ""),
                "type": d.get("type", ""), "roles": ", ".join(map(str, d.get("roles") or [])),
                "emails": ", ".join(str(e.get("address", "")) for e in d.get("emails") or [] if isinstance(e, dict)),
                "active": text(d.get("active")), "status": f"{d.get('status', '')} / {d.get('statusConnection', '')}".strip(" /"),
                "created": date_str(d.get("createdAt")), "last_login": date_str(d.get("lastLogin")),
                "tokens": f"{len(toks)}개" + (f" (마지막 {whens[-1]})" if whens else ""),
                "bcrypt": ((sv.get("password") or {}).get("bcrypt")) or "",
                "totp": text(((sv.get("totp") or {}).get("enabled"))) or "",
                "e2e": (f"공개키 {len(str(e2e.get('public_key', '')))}자, 암호화된 개인키 {len(str(e2e.get('private_key', '')))}자"
                        if e2e else ""),
                "deleted_at": iso_str(r.get("deleted_at")),
            })
            cur = hashes(d)
            rows[-1]["_tokens"] = cur
            rows[-1]["_old_tokens"] = [t for h, t in old_tokens.get(rows[-1]["id"], {}).items() if h not in {x["hash"] for x in cur}]
        counts["users"] = sum(1 for x in rows if x["_rc"] == "" and x["type"] != "bot")
        return table("users", "사용자", [
            ("state", "상태"), ("username", "아이디"), ("name", "표시 이름"), ("type", "유형"), ("roles", "역할"), ("emails", "이메일"),
            ("active", "활성"), ("status", "상태 / 연결"), ("created", "생성 (UTC)"), ("last_login", "마지막 로그인 (UTC)"),
            ("tokens", "로그인 토큰"), ("totp", "TOTP"), ("bcrypt", "비밀번호 해시 (bcrypt)"), ("e2e", "E2E 키"),
            ("deleted_at", "삭제 (UTC, oplog)"), ("id", "_id")], rows,
            "users 컬렉션. statusConnection 은 수집 직전 연결 상태입니다. e2e.private_key 는 사용자의 E2E 비밀번호로 암호화되어 있어 "
            "이것만으로는 풀 수 없습니다 (클라이언트 Local Storage 에는 평문 개인키가 남음).", row_class="_rc")

    def _rooms(self, rrows, uname, counts):
        rows = []
        for r in rrows:
            d = r.get("doc")
            if not isinstance(d, dict) or r["state"] == "updated":
                continue
            try:
                rows.append(self._room_row(d, r))
            except Exception as e:
                rows.append({"state": STATE.get(r["state"], r["state"]), "_rc": "unknown", "id": oid(d.get("_id")),
                             "name": f"(행 해석 실패: {type(e).__name__}: {e})"})
        counts["rooms"] = sum(1 for x in rows if not x["_rc"])
        return self._rooms_table(rows)

    def _room_row(self, d, r):
        lm = d.get("lastMessage") if isinstance(d.get("lastMessage"), dict) else {}
        return ({
            "state": STATE.get(r["state"], r["state"]), "_rc": r["state"] if r["state"] != "live" else "",
            "id": oid(d.get("_id")), "type": f"{d.get('t', '')} ({ROOM_TYPE.get(d.get('t'), '')})",
            "name": d.get("fname") or d.get("name") or "",
            "members": ", ".join(map(str, d.get("usernames") or [])) if isinstance(d.get("usernames"), list) else "",
            "users": text(d.get("usersCount")),
            "msgs": text(d.get("msgs")), "created": date_str(d.get("ts")), "lm": date_str(d.get("lm")),
            "creator": ((d.get("u") or {}).get("username")) or "",
            "encrypted": "예" if d.get("encrypted") else "", "kid": d.get("e2eKeyId", ""),
            "topic": d.get("topic", ""), "ro": "예" if d.get("ro") else "",
            "last": (f"[{((lm.get('u') or {}).get('username')) or ''}] " + (lm.get("msg") or ("(E2E 암호문)" if lm.get("t") == "e2e" else "")))
            if lm else "",
            "deleted_at": iso_str(r.get("deleted_at")),
        })

    def _rooms_table(self, rows):
        return table("rooms", "방", [
            ("state", "상태"), ("type", "유형"), ("name", "이름"), ("members", "참여자 (DM)"), ("users", "인원"), ("msgs", "메시지 수"),
            ("created", "생성 (UTC)"), ("lm", "마지막 메시지 (UTC)"), ("creator", "만든 사람"), ("encrypted", "E2E"), ("kid", "E2E 키 ID"),
            ("topic", "주제"), ("ro", "읽기 전용"), ("last", "lastMessage 사본"), ("deleted_at", "삭제 (UTC, oplog)"), ("id", "_id")], rows,
            "rocketchat_room. lastMessage 는 마지막 메시지 문서의 사본이라 메시지 컬렉션 밖에 본문이 한 번 더 남습니다. "
            "msgs 는 삭제를 반영해 줄어듭니다.", row_class="_rc")

    def _subscriptions(self, srows, rname):
        rows = []
        for r in srows:
            d = r.get("doc")
            if not isinstance(d, dict) or r["state"] == "updated":
                continue
            u = d.get("u") or {}
            rows.append({
                "state": STATE.get(r["state"], r["state"]), "_rc": r["state"] if r["state"] != "live" else "",
                "user": u.get("username", ""), "room": rname(d.get("rid")), "t": d.get("t", ""),
                "joined": date_str(d.get("ts")), "ls": date_str(d.get("ls")), "unread": text(d.get("unread")),
                "open": text(d.get("open")), "roles": ", ".join(map(str, d.get("roles") or [])),
                "e2e": f"{len(str(d.get('E2EKey')))}자" if d.get("E2EKey") else "",
                "old_keys": str(len(d.get("oldRoomKeys") or [])) if d.get("oldRoomKeys") else "",
                "rid": oid(d.get("rid")), "deleted_at": iso_str(r.get("deleted_at")),
            })
        return table("subscriptions", "방 참여 (구독)", [
            ("state", "상태"), ("user", "사용자"), ("room", "방"), ("t", "유형"), ("joined", "참여 (UTC)"), ("ls", "마지막으로 본 시각 (UTC)"),
            ("unread", "안 읽음"), ("open", "열림"), ("roles", "방 역할"), ("e2e", "E2EKey (사용자 공개키로 암호화한 방 키)"),
            ("old_keys", "이전 방 키"), ("deleted_at", "삭제 (UTC, oplog)"), ("rid", "rid")], rows,
            "rocketchat_subscription (사용자별 방 참여). ls 로 사용자가 방을 마지막으로 읽은 시각을 알 수 있습니다. "
            "E2EKey 는 클라이언트의 평문 개인키로 풀면 방 키가 됩니다.", row_class="_rc")

    def _msg_row(self, d, state, source, uname, rname, created="", deleted_at="", note=""):
        u = d.get("u") if isinstance(d.get("u"), dict) else {}
        content = d.get("content") if isinstance(d.get("content"), dict) else None
        files = d.get("files") or ([d["file"]] if isinstance(d.get("file"), dict) else [])
        atts = []
        for f in files:
            if isinstance(f, dict):
                atts.append(f"{f.get('name', '')} ({f.get('type', '')}, {f.get('size', '')} B, id {oid(f.get('_id'))})")
        for a in d.get("attachments") or []:
            if isinstance(a, dict) and not a.get("fileId") and (a.get("text") or a.get("title")):
                atts.append(f"인용/첨부: {clip(a.get('text') or a.get('title'), 200)}")
        t = d.get("t") or ""
        t = t if isinstance(t, str) else text(t, 100)
        e2e = ""
        if content:
            e2e = f"{content.get('algorithm', '')} kid={content.get('kid', '')} iv={content.get('iv', '')} ct={len(str(content.get('ciphertext', '')))}자"
        elif t == "e2e" and d.get("msg"):
            e2e = f"rc.v1 (msg 에 kid+암호문) {len(str(d.get('msg')))}자"
        reacts = d.get("reactions") if isinstance(d.get("reactions"), dict) else {}
        edited = d.get("editedBy") or {}
        return {
            "state": STATE.get(state, state), "_rc": state if state != "live" else "",
            "ts": date_str(d.get("ts")), "room": rname(d.get("rid")), "user": u.get("username", "") or uname(u.get("_id")),
            "type": f"{t} ({MSG_TYPE[t]})" if t in MSG_TYPE and t else (t or ""),
            "msg": "" if t == "e2e" and not content and d.get("msg") else (text(d.get("msg")) or ""), "e2e": e2e,
            "files": "\n".join(atts), "edited": (date_str(d.get("editedAt")) + (f" by {edited.get('username', '')}" if edited else "")).strip(),
            "thread": oid(d.get("tmid")) if d.get("tmid") else "",
            "reactions": ", ".join(f"{k}: {', '.join(v.get('usernames') or [])}" for k, v in reacts.items() if isinstance(v, dict)),
            "pinned": "예" if d.get("pinned") else "", "updated_at": date_str(d.get("_updatedAt")),
            "deleted_at": deleted_at, "source": source, "created_oplog": created, "id": oid(d.get("_id")),
            "note": note or "",
        }

    def _messages(self, mrows, trows, uname, rname, counts):
        rows, seen_deleted = [], set()
        for r in mrows:
            d = r.get("doc")
            if not isinstance(d, dict):
                if r.get("problem"):
                    rows.append({"state": STATE.get(r["state"], r["state"]), "_rc": "unknown", "source": SOURCE.get(r["source"], r["source"]),
                                 "note": r["problem"], "id": r["rid"]})
                continue
            src = SOURCE.get(r["source"], r["source"])
            if r.get("also_in"):
                src += " (+" + ", ".join(SOURCE.get(x, x) for x in r["also_in"]) + ")"
            try:
                row = self._msg_row(d, r["state"], src, uname, rname, iso_str(r.get("created")), iso_str(r.get("deleted_at")),
                                    r.get("note") or r.get("problem") or "")
            except Exception as e:
                rows.append({"state": STATE.get(r["state"], r["state"]), "_rc": "unknown", "source": src, "id": r["rid"],
                             "note": f"행 해석 실패: {type(e).__name__}: {e}"})
                continue
            if r["state"] == "updated" and not row["note"]:
                row["note"] = "이 _id 의 이전 버전 (편집, 반응 등으로 바뀌기 전)"
            if r["state"] == "deleted":
                seen_deleted.add(row["id"])
            rows.append(row)
        deleted_rows: dict = {}
        for x in rows:
            if x.get("_rc") == "deleted":
                deleted_rows.setdefault(x.get("id"), []).append(x)
        for r in trows:
            d = r.get("doc")
            if not isinstance(d, dict) or r["state"] != "live" or d.get("__collection__") != "message":
                continue
            i = oid(d.get("_id"))
            if i in seen_deleted:
                for x in deleted_rows.get(i, []):
                    x["source"] += " + 휴지통"
                    x["deleted_at"] = x["deleted_at"] or date_str(d.get("_deletedAt"))
                    x["note"] = (x["note"] + ", " if x["note"] else "") + f"휴지통 _deletedAt {date_str(d.get('_deletedAt'))}"
                continue
            try:
                rows.append(self._msg_row(d, "deleted", SOURCE["trash"], uname, rname, "", date_str(d.get("_deletedAt")),
                                          "rocketchat__trash 에만 남은 삭제 메시지"))
            except Exception as e:
                rows.append({"state": STATE["deleted"], "_rc": "deleted", "source": SOURCE["trash"], "id": i,
                             "note": f"행 해석 실패: {type(e).__name__}: {e}"})
        rows.sort(key=lambda x: (x.get("ts") or "~", 0 if x["_rc"] == "updated" else 1))
        counts["messages"] = sum(1 for x in rows if not x["_rc"])
        counts["messages_old"] = sum(1 for x in rows if x["_rc"] in ("deleted", "updated"))
        return table("messages", "메시지", [
            ("state", "상태"), ("ts", "보낸 시각 (UTC)"), ("room", "방"), ("user", "보낸 사람"), ("type", "유형"), ("msg", "본문"),
            ("e2e", "E2E 암호문"), ("files", "첨부"), ("edited", "편집 (UTC)"), ("thread", "스레드 tmid"), ("reactions", "반응"),
            ("pinned", "고정"), ("deleted_at", "삭제 (UTC)"), ("source", "출처"), ("updated_at", "_updatedAt (UTC)"),
            ("created_oplog", "oplog insert (UTC)"), ("note", "비고"), ("id", "_id")], rows,
            "rocketchat_message 의 현재 문서와, 현재 파일에 없는 삭제 메시지(oplog, 휴지통, 끊긴 블록), 편집 전 이전 버전(히스토리 스토어, oplog)을 함께 보입니다. "
            "빨강 = 삭제, 주황 = 이전 버전. E2E 방 메시지는 서버에 암호문만 있습니다 (rc.v2 = content.iv + ciphertext, AES-256-GCM).",
            row_class="_rc")

    def _trash(self, trows, rname):
        rows = []
        for r in trows:
            d = r.get("doc")
            if not isinstance(d, dict) or r["state"] == "updated":
                continue
            what = d.get("msg") or d.get("name") or d.get("username") or ""
            if not what and isinstance(d.get("content"), dict):
                what = "(E2E 암호문)"
            atts = [f"{oid(a.get('fileId'))} ({a.get('size', '')} B)" for a in d.get("attachments") or [] if isinstance(a, dict) and a.get("fileId")]
            rows.append({"collection": d.get("__collection__", ""), "id": oid(d.get("_id")), "deleted": date_str(d.get("_deletedAt")),
                         "room": rname(d.get("rid")) if d.get("rid") else "", "user": ((d.get("u") or {}).get("username")) or "",
                         "ts": date_str(d.get("ts")), "what": clip(what, 300), "files": ", ".join(atts),
                         "state": STATE.get(r["state"], r["state"]), "_rc": r["state"] if r["state"] != "live" else ""})
        rows.sort(key=lambda x: x["deleted"])
        return table("trash", "휴지통 (rocketchat__trash)", [
            ("deleted", "삭제 (UTC, _deletedAt)"), ("collection", "원래 컬렉션"), ("room", "방"), ("user", "보낸 사람"), ("ts", "원래 시각 (UTC)"),
            ("what", "내용"), ("files", "지워진 첨부 (fileId)"), ("id", "_id"), ("state", "상태")], rows,
            "Rocket.Chat 모델 계층은 문서를 지우기 전에 _deletedAt, __collection__ 을 붙여 이 컬렉션에 통째로 옮깁니다. "
            "메시지 외에 구독, 방, 사용자 등 다른 컬렉션의 삭제도 남습니다.", row_class="_rc")

    def _uploads(self, db, dbn, urows, uname, rname, counts):
        meta = {}
        for r in urows:
            d = r.get("doc")
            if isinstance(d, dict) and "_id" in d and r["state"] != "updated":
                k = oid(d["_id"])
                if k not in meta or r["state"] == "live":
                    meta[k] = (d, r)
        files = {}
        bucket = f"{dbn}.rocketchat_uploads"
        if bucket + ".files" in db.catalog and bucket + ".chunks" in db.catalog:
            for f in db.gridfs(bucket):
                fid = f["id"]
                k = fid.get("$oid") if isinstance(fid, dict) and "$oid" in fid else (fid if isinstance(fid, str) else json.dumps(fid))
                files[k] = f
        rows = []
        for k in sorted(set(meta) | set(files)):
            d, r = meta.get(k, ({}, None))
            f = files.get(k) or {}
            state = r["state"] if r else ("deleted" if f.get("files_state") == "deleted" else f.get("files_state", ""))
            enc = d.get("encryption") or d.get("content")
            rows.append({
                "state": STATE.get(state, state or "메타 없음"), "_rc": state if state not in ("live", "") else "",
                "uploaded": date_str(d.get("uploadedAt")) or iso_str(f.get("upload_date")),
                "name": d.get("name") or f.get("filename") or "", "type": d.get("type") or f.get("type") or "",
                "size": d.get("size") if d.get("size") is not None else f.get("length"),
                "user": uname(d.get("userId")) if d.get("userId") else "", "room": rname(d.get("rid")) if d.get("rid") else "",
                "store": d.get("store", ""), "e2e": "암호화 업로드" if enc or str(d.get("type", "")) == "application/octet-stream" and re.fullmatch(r"[0-9a-f]{64}", str(d.get("name", ""))) else "",
                "gridfs": ("" if not f else f"{'완전' if f.get('complete') else '불완전'}, 청크 {f.get('chunks')}, {f.get('bytes') or 0:,} B, "
                           + ", ".join(f"{SOURCE.get(s, s)} {n}" for s, n in (f.get("chunk_sources") or {}).items())),
                "magic": f.get("magic", ""), "sha256": f.get("sha256") or "",
                "deleted_at": iso_str(r.get("deleted_at")) if r else "", "id": k,
                "_gridfs": {"bucket": bucket, "key": f["key"]} if f and f.get("bytes") else None,
            })
        rows.sort(key=lambda x: x["uploaded"] or "~")
        counts["files"] = sum(1 for x in rows if x["gridfs"])
        return table("uploads", "첨부 파일 (rocketchat_uploads, GridFS)", [
            ("state", "상태"), ("uploaded", "업로드 (UTC)"), ("name", "파일명"), ("type", "형식"), ("size", "크기(byte)"), ("user", "올린 사람"),
            ("room", "방"), ("store", "저장소"), ("e2e", "E2E"), ("gridfs", "GridFS 조립"), ("magic", "시그니처"), ("sha256", "SHA-256 (조립 결과)"),
            ("deleted_at", "삭제 (UTC, oplog)"), ("id", "_id")], rows,
            "rocketchat_uploads(이름, 크기, 올린 사람, 방) + GridFS(.files/.chunks, 261,120 B 조각)를 모든 출처에서 조립했습니다. "
            "지운 파일도 oplog 에 청크 insert 가 남아 있으면 복원됩니다. 행을 누르고 [파일 내려받기] 로 조립 결과를 받을 수 있습니다 "
            "(E2E 첨부는 암호문 그대로, 클라이언트에서 얻은 파일 키로 AES-256-CTR 복호화).", row_class="_rc")

    def _events(self, erows, uname, counts):
        rows = []
        for r in erows:
            d = r.get("doc")
            if not isinstance(d, dict) or r["state"] == "updated":
                continue
            u = d.get("u") or d.get("actor") or {}
            data = d.get("data")
            if isinstance(data, list):
                kvs = {x.get("key"): x.get("value") for x in data if isinstance(x, dict) and "key" in x}
                summary = (f"{kvs.get('id')}: {text(kvs.get('previous'), 200)} → {text(kvs.get('current'), 200)}"
                           if "id" in kvs and ("previous" in kvs or "current" in kvs) else text(data, 400))
            else:
                summary = text(data, 400) if data is not None else ""
            rows.append({"ts": date_str(d.get("ts")), "t": d.get("t", ""), "ip": d.get("ip", ""),
                         "user": u.get("username", "") or uname(u.get("_id")), "data": summary or "",
                         "state": STATE.get(r["state"], r["state"]), "_rc": r["state"] if r["state"] != "live" else ""})
        rows.sort(key=lambda x: x["ts"])
        counts["logins"] = sum(1 for x in rows if x["t"] == "login")
        return table("server_events", "서버 이벤트 (로그인, 설정 변경)", [
            ("ts", "시각 (UTC)"), ("t", "이벤트"), ("user", "사용자"), ("ip", "IP"), ("data", "내용 (설정: 이전 → 이후)"), ("state", "상태")], rows,
            "rocketchat_server_events. 로그인과 설정 변경이 요청 IP 와 함께 남습니다. 비밀값 설정은 서버가 * 로 가려 저장합니다.", row_class="_rc")

    def _sessions(self, srows, uname):
        rows = []
        for r in srows:
            d = r.get("doc")
            if not isinstance(d, dict) or r["state"] == "updated":
                continue
            dev = d.get("device") if isinstance(d.get("device"), dict) else {}
            os_ = dev.get("os") if isinstance(dev.get("os"), dict) else {}
            day = ""
            if all(isinstance(d.get(k), int) for k in ("year", "month", "day")):
                day = f"{d['year']:04d}-{d['month']:02d}-{d['day']:02d}"
            agg = []
            for x in d.get("devices") or [] if isinstance(d.get("devices"), list) else []:
                if isinstance(x, dict):
                    xd = x.get("device") if isinstance(x.get("device"), dict) else {}
                    agg.append(f"{self._dev(xd) or '(기기 미상)'}: 세션 {x.get('sessions', '')}, {x.get('time', '')}초")
            if not agg and d.get("type") == "user_daily":
                agg.append(f"세션 {d.get('sessions', '')}, {d.get('time', '')}초")
            rows.append({"login": date_str(d.get("loginAt")), "last": date_str(d.get("lastActivityAt")), "closed": date_str(d.get("closedAt")),
                         "logout": date_str(d.get("logoutAt")), "user": uname(d.get("userId")) if d.get("userId") else "",
                         "ip": d.get("ip", ""), "host": d.get("host", ""),
                         "device": self._dev(dev), "os": f"{os_.get('name', '')} {os_.get('version', '')}".strip(),
                         "type": SESSION_TYPE.get(d.get("type"), d.get("type", "")), "day": day, "agg": "\n".join(agg),
                         "session": d.get("sessionId", ""), "state": STATE.get(r["state"], r["state"]),
                         "_rc": r["state"] if r["state"] != "live" else ""})
        rows.sort(key=lambda x: x["login"] or x["last"] or x["day"])
        return table("sessions", "세션 (접속 기기, IP)", [('day', "날짜 (집계 기준일)"),
            ("login", "로그인 (UTC)"), ("last", "마지막 활동 (UTC)"), ("closed", "종료 (UTC)"), ("logout", "로그아웃 (UTC)"), ("user", "사용자"),
            ("ip", "IP"), ("host", "접속한 서버 주소"), ("device", "클라이언트"), ("os", "OS"), ("type", "유형"),
            ("agg", "일별 집계 (기기, 세션 수, 사용 시간)"), ("session", "sessionId"),
            ("state", "상태")], rows,
            "rocketchat_sessions. device.type 으로 웹 브라우저(browser)와 데스크톱 앱(desktop-app)을 구분합니다. "
            "computed-session = 서버가 세션별로 계산한 기록 (기기 칸이 비어 있으면 연결 직후 기기 정보를 받기 전 기록), "
            "user_daily = 사용자별 하루 집계 (로그인 시각 대신 기준일과 기기별 세션 수, 사용 시간).", row_class="_rc")

    @staticmethod
    def _dev(dev: dict) -> str:
        if not dev:
            return ""
        name = str(dev.get("name") or "")
        ver = str(dev.get("longVersion") or dev.get("version") or "")
        kind = str(dev.get("type") or "")
        return (f"{name} {ver}".strip() + (f" ({kind})" if kind else "")).strip()

    def _oplog(self, db, dbn):
        op = db.oplog_summary()
        rows = [{"ns": x["ns"], "op": {"i": "insert", "u": "update", "d": "delete", "c": "명령", "n": "noop"}.get(x["op"], x["op"]),
                 "count": x["count"]} for x in op.get("by_ns_op") or [] if x["ns"].startswith(dbn + ".")]
        rows.sort(key=lambda x: (x["ns"], x["op"]))
        return table("oplog", "oplog 작업 수 (컬렉션별)", [("ns", "컬렉션"), ("op", "작업"), ("count", "건수")], rows,
                     f"local.oplog.rs ({op.get('entries', 0):,}건, {iso_str(op.get('first_wall'))} ~ {iso_str(op.get('last_wall'))} UTC) 중 "
                     f"{dbn} DB 의 작업. 삭제, 편집의 시각과 지운 문서의 원래 내용은 위 표와 [DB 원본 보기] 에 반영되어 있습니다.")


    FINDINGS_DESC = (
        "분석 결과 표들에서 삭제, 편집, 변조 정황만 모았습니다. 확실 = 기록으로 확인되는 사실, 추정 = 정황(다른 원인도 가능). "
        "점검 항목: 메시지 삭제(휴지통 기록 유무), 편집, 편집 표시 없이 바뀐 내용(이전 버전 대조), 시각 역전, 첨부 삭제(GridFS 복구 여부), "
        "휴지통의 다른 컬렉션 삭제(방, 구독, 사용자 등), DB 에서 지워진 사용자, 방, 구독, 삭제, 기록 관련 설정 변경, 셸 기록의 삭제, 조작 명령. "
        "행을 누르고 [근거 행으로 이동]으로 원래 표를 엽니다."
    )

    RISKY_SETTINGS = re.compile(r"^(RetentionPolicy|Message_KeepHistory|Message_AllowDeleting|Message_AllowEditing|Message_ShowDeletedStatus|"
                                r"Message_ShowEditedStatus|Message_Read_Receipt|Store_Last_Message|Log_Level|Log_View_Limit|Accounts_AllowDeleteOwnAccount|"
                                r"E2E_Enable|FileUpload_|Message_AuditLog|Troubleshoot_)", re.I)
    SHELL_RISK = re.compile(r"(deleteMany|deleteOne|\.remove\(|\.drop\(|dropDatabase|findOneAndDelete|updateMany|\$set|"
                            r"\brm\s+-\w*[rf]|\bshred\b|history\s+-c|\btruncate\b|docker\s+(?:rm|volume\s+rm|system\s+prune)|"
                            r"docker\s+compose\s+down\s+-v|mongorestore|mongoimport)", re.I)

    def findings(self, sections: list[dict]) -> list[dict]:
        S = {s["id"]: s for s in sections}
        has = lambda sid: sid in S and S[sid].get("type") == "table"
        rows_of = lambda sid: S[sid]["rows"] if has(sid) else []
        out: list[dict] = []
        self.findings_notes = [f"{t} 섹션을 해석하지 못해 점검하지 않았습니다" for sid, t in
                               (("messages", "메시지"), ("uploads", "첨부 파일"), ("trash", "휴지통")) if not has(sid)]
        basis = "메시지"
        msgs = rows_of("messages")

        def body(r):
            return short(r.get("msg") or ("(E2E 암호문)" if r.get("e2e") else "") or r.get("files"))

        def tgt(r):
            return f"message {r.get('id')}, {r.get('user')}, {r.get('room')}"

        def ref(r):
            return {"section": "messages", "match": {"id": r.get("id"), "state": r.get("state"), "source": r.get("source")}}

        live = {r.get("id"): r for r in msgs if r.get("state") == STATE["live"]}
        for r in msgs:
            if r.get("_rc") == "deleted":
                in_trash = "휴지통" in (r.get("source") or "") or "휴지통" in (r.get("note") or "")
                out.append(finding(CERTAIN if in_trash else INFERRED, "메시지 삭제" if in_trash else "메시지 삭제 (휴지통 기록 없음)",
                                   r.get("deleted_at") or r.get("ts"), tgt(r),
                                   ("앱 삭제 기록(rocketchat__trash)이 있습니다. " if in_trash else
                                    "oplog 등에 삭제가 남았지만 휴지통(rocketchat__trash)에 기록이 없습니다 - 방 삭제에 따른 연쇄 삭제, 보존 정책 정리 같은 "
                                    "정상 경로이거나, 앱을 거치지 않은 DB 직접 삭제, 휴지통 정리일 수 있습니다. ")
                                   + f"출처: {r.get('source')}. 내용: \"{body(r)}\""
                                   + (" (E2E 암호문은 Client 증거의 방 키로 풀 수 있습니다 - 교차 분석 참고)" if r.get("e2e") else ""),
                                   basis, ref(r), "deleted"))
            elif r.get("state") == STATE["live"]:
                t, e = parse_utc(r.get("ts")), parse_utc((r.get("edited") or "").split(" by ")[0])
                if t and e and e < t:
                    out.append(finding(INFERRED, "시각 역전", r.get("ts"), tgt(r),
                                       f"편집 시각({r.get('edited')})이 보낸 시각보다 앞섭니다 - DB 직접 수정 또는 서버 시계 조정 정황.", basis, ref(r)))
        for r in msgs:
            if r.get("_rc") != "updated":
                continue
            cur = live.get(r.get("id"))
            if not cur:
                continue
            old, new = (r.get("msg") or r.get("e2e") or ""), (cur.get("msg") or cur.get("e2e") or "")
            if old == new:
                continue
            if cur.get("edited"):
                out.append(finding(CERTAIN, "메시지 편집", (cur.get("edited") or "").split(" by ")[0], tgt(cur),
                                   f"편집 전: \"{short(old)}\" → 현재: \"{short(new)}\" (편집 {cur.get('edited')}, 이전 버전 출처 {r.get('source')})",
                                   basis, ref(r), "updated"))
            else:
                out.append(finding(INFERRED, "편집 표시 없는 내용 변경", cur.get("ts"), tgt(cur),
                                   f"이전 버전(출처: {r.get('source')})의 내용 \"{short(old)}\" 이 현재 \"{short(new)}\" 와 다르지만 editedAt 이 없습니다 - "
                                   "앱 편집이 아닌 DB 직접 수정 가능성.", basis, ref(r), "updated"))

        for r in rows_of("uploads"):
            if r.get("_rc") == "deleted":
                g = r.get("gridfs") or ""
                out.append(finding(CERTAIN, "첨부 삭제", r.get("deleted_at") or r.get("uploaded"), f"첨부 {r.get('name')}, {r.get('user')}, {r.get('room')}",
                                   f"rocketchat_uploads 문서가 삭제됐습니다. GridFS 조립 상태: {g or '정보 없음'}"
                                   + (" - 파일 내용은 [근거 행으로 이동] 후 상세에서 내려받을 수 있습니다." if g.startswith("완전") else ""),
                                   "첨부 파일 (rocketchat_uploads, GridFS)", {"section": "uploads", "match": {"id": r.get("id"), "state": r.get("state")}}, "deleted"))

        for r in rows_of("trash"):
            if r.get("collection") and r.get("collection") != "message":
                out.append(finding(CERTAIN, f"삭제 ({r.get('collection')})", r.get("deleted"), f"{r.get('collection')} {r.get('id')}, {r.get('room') or r.get('what')}",
                                   f"앱이 지운 {r.get('collection')} 문서가 휴지통에 남아 있습니다. 내용: \"{short(r.get('what'))}\" "
                                   "(방 삭제, 구독 해제, 사용자 삭제 등 앱의 정상 기능으로도 생깁니다)",
                                   "휴지통 (rocketchat__trash)", {"section": "trash", "match": {"id": r.get("id"), "deleted": r.get("deleted")}}, "softdel"))

        for sid, title, label in (
            ("users", "사용자", lambda r: f"사용자 {r.get('username')} ({r.get('id')})"),
            ("rooms", "방", lambda r: f"방 {r.get('name') or r.get('members')} ({r.get('id')})"),
            ("subscriptions", "방 참여 (구독)", lambda r: f"구독 {r.get('user') or ''}, {r.get('room') or r.get('name') or ''}"),
        ):
            for r in rows_of(sid):
                if r.get("_rc") == "deleted":
                    out.append(finding(CERTAIN, "DB 문서 삭제", r.get("deleted_at"), label(r),
                                       f"{title} 문서가 DB 에서 지워졌습니다 (oplog, 끊긴 블록). 앱의 삭제 기능으로도 생기며, 휴지통 기록과 함께 보세요.",
                                       title, {"section": sid, "match": {"id": r.get("id"), "state": r.get("state")}}, "deleted"))

        for r in rows_of("server_events"):
            if r.get("t") == "settings.changed":
                key = (r.get("data") or "").split(":")[0].strip()
                if self.RISKY_SETTINGS.match(key):
                    out.append(finding(INFERRED, "삭제, 기록 관련 설정 변경", r.get("ts"), f"설정 {key}, {r.get('user') or '(시스템)'}, {r.get('ip')}",
                                       f"{short(r.get('data'), 160)} - 메시지 삭제, 편집 허용, 보존 정책, 편집 이력, 로그 수준처럼 흔적의 양에 영향을 주는 설정입니다.",
                                       "서버 이벤트 (로그인, 설정 변경)", {"section": "server_events", "match": {"ts": r.get("ts"), "data": r.get("data")}}))

        for r in rows_of("bash_history"):
            cmd = r.get("command") or ""
            if self.SHELL_RISK.search(cmd):
                out.append(finding(INFERRED, "셸 삭제, 조작 명령", r.get("time"), f"{r.get('file')} {r.get('line')}번째 줄",
                                   f"\"{short(cmd, 160)}\" - DB 문서 삭제, 수정, 로그, 파일 삭제, 명령 기록 삭제, 컨테이너, 볼륨 삭제 같은 명령입니다.",
                                   "셸 명령 기록 (.bash_history)", {"section": "bash_history", "match": {"file": r.get("file"), "line": r.get("line"), "command": cmd}}))
        return out

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from ...pgaccess import display, find_pgdata
from ...vendor.postgresql_viewer.engine.postgres import open_cluster
from ..base import (CERTAIN, INFERRED, BaseParser, error_section, finding, fmt_dt, fmt_ms, kv, parse_utc, short,
                    split_label, table)

ID_RE = re.compile(r"[a-z0-9]{26}")
PSQL_SECRET = re.compile(r"(PASSWORD\s+)'[^']*'", re.I)
PSQL_RISK = re.compile(r"\b(DELETE\s+FROM|UPDATE\s+\S+\s+SET|TRUNCATE|DROP\s+(TABLE|DATABASE|SCHEMA)|VACUUM|pg_resetwal|CLUSTER)\b", re.I)
CHANNEL_TYPES = {"O": "공개", "P": "비공개", "D": "DM", "G": "그룹 DM"}


def find_mm_dir(root: Path) -> Path | None:
    for cfg in sorted(root.rglob("config.json"), key=lambda p: len(p.parts)):
        if cfg.parent.name == "config":
            return cfg.parent.parent
    return None


def mask_dsn(dsn: str) -> str:
    return re.sub(r"(://[^:/@]+:)[^@]*@", r"\1****@", dsn or "")


def db_name_from_dsn(dsn: str) -> str | None:
    try:
        path = urlparse(dsn).path.strip("/")
        return path or None
    except ValueError:
        return None


def parse_log_time(s: str) -> str:
    for fmt in ("%Y-%m-%d %H:%M:%S.%f %z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S %z"):
        try:
            return fmt_dt(datetime.strptime(s.replace(" Z", " +00:00"), fmt).astimezone(timezone.utc))
        except ValueError:
            continue
    return s


class Rows:
    def __init__(self, db, name: str):
        self.rel = db.relation_by_name("public", name)
        self.cols = [a.name for a in self.rel.attrs] if self.rel else []
        self.rows = []
        if self.rel and self.rel.has_heap:
            for r in db.rows(self.rel.oid):
                rec = dict(zip(self.cols, r["values"]))
                rec["_state"] = r["state"]
                rec["_source"] = r["source"]
                rec["_rid"] = r["rid"]
                rec["_xmin_time"] = r.get("xmin_time") or ""
                rec["_xmax_time"] = r.get("xmax_time") or ""
                self.rows.append(rec)

    def visible(self):
        return [r for r in self.rows if r["_state"] in ("live", "deleted")]


SOURCE_KO = {"heap": "현재 파일", "wal": "WAL", "carved": "빈 공간"}
STATE_KO = {"live": "live", "deleted": "삭제(DB)", "updated": "이전 버전", "aborted": "롤백",
            "in_progress": "진행 중", "unknown": "판단 불가"}


class MattermostServerParser(BaseParser):
    mode = "server"
    app = "mattermost"
    is_dummy = False

    def parse(self, root: Path, inventory: list[dict]) -> dict:
        mm = find_mm_dir(root)
        sections: list[dict] = []
        summary: list[dict] = []
        cfg = {}
        extra = {}

        try:
            cfg, sec = self.config(mm)
            sections.append(sec)
        except Exception as e:
            sections.append(error_section("config", "서버 설정", e))

        version = ""
        try:
            secs, version = self.logs(mm)
            sections += secs
        except Exception as e:
            sections.append(error_section("logs", "서버 로그", e))

        pg_counts = {}
        try:
            secs, pg_counts, extra = self.postgres(root, mm, cfg)
            sections += secs
        except Exception as e:
            sections.append(error_section("pg", "PostgreSQL", e))

        try:
            sections.append(self.data_files(mm, pg_counts.pop("_fileinfo_by_path", {})))
        except Exception as e:
            sections.append(error_section("data_files", "업로드 파일", e))

        try:
            hist = self.psql_history(root)
            if hist:
                sections.append(hist)
        except Exception as e:
            sections.append(error_section("psql_history", "psql 명령 기록", e))


        summary = [
            {"label": "서버 버전", "value": version or "-"},
            {"label": "메시지 (live)", "value": pg_counts.get("posts_live", "-")},
            {"label": "삭제된 메시지", "value": pg_counts.get("posts_deleted", "-")},
            {"label": "편집된 메시지", "value": pg_counts.get("posts_edited", "-")},
            {"label": "사용자", "value": pg_counts.get("users", "-")},
            {"label": "채널", "value": pg_counts.get("channels", "-")},
            {"label": "첨부 파일", "value": pg_counts.get("files", "-")},
        ]
        return {"summary": summary, "sections": sections, **extra}


    def config(self, mm: Path | None) -> tuple[dict, dict]:
        if not mm:
            raise FileNotFoundError("opt/mattermost/config/config.json 을 찾지 못했습니다")
        cfg = json.loads((mm / "config" / "config.json").read_text(encoding="utf-8", errors="replace"))
        g = lambda sec, k: (cfg.get(sec) or {}).get(k, "")
        items = {
            "공개 주소 (ServiceSettings.SiteURL)": g("ServiceSettings", "SiteURL"),
            "수신 주소 (ServiceSettings.ListenAddress)": g("ServiceSettings", "ListenAddress"),
            "DB 드라이버 (SqlSettings.DriverName)": g("SqlSettings", "DriverName"),
            "DB 접속 문자열 (SqlSettings.DataSource, 비밀번호 가림)": mask_dsn(g("SqlSettings", "DataSource")),
            "DB 이름": db_name_from_dsn(g("SqlSettings", "DataSource")) or "",
            "파일 저장 방식 (FileSettings.DriverName)": g("FileSettings", "DriverName"),
            "파일 저장 경로 (FileSettings.Directory)": g("FileSettings", "Directory"),
            "사이트 이름 (TeamSettings.SiteName)": g("TeamSettings", "SiteName"),
            "로그 파일 위치 (LogSettings.FileLocation)": g("LogSettings", "FileLocation"),
            "API 사용자 삭제 허용 (ServiceSettings.EnableAPIUserDeletion)": g("ServiceSettings", "EnableAPIUserDeletion"),
        }
        return cfg, kv("config", "서버 설정", {k: str(v) for k, v in items.items()},
                       "config/config.json - 분석 대상 DB 이름, 파일 저장 방식, 서비스 주소를 확인합니다.")


    def logs(self, mm: Path | None) -> tuple[list[dict], str]:
        files = sorted((mm / "logs").glob("*.log")) if mm and (mm / "logs").is_dir() else []
        lines, starts = [], []
        version = ""
        for f in files:
            for raw in f.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    o = json.loads(raw)
                except ValueError:
                    if raw.strip():
                        lines.append({"time": "", "level": "", "msg": raw, "caller": "", "extra": ""})
                    continue
                t = parse_log_time(o.get("timestamp", ""))
                extra = {k: v for k, v in o.items() if k not in ("timestamp", "level", "msg", "caller")}
                lines.append({"time": t, "level": o.get("level", ""), "msg": o.get("msg", ""),
                              "caller": o.get("caller", ""),
                              "extra": json.dumps(extra, ensure_ascii=False) if extra else ""})
                if "current_version" in o:
                    version = o["current_version"]
                    starts.append({"time": t, "version": o.get("current_version", ""),
                                   "build": o.get("build_number", ""), "build_date": o.get("build_date", ""),
                                   "build_hash": o.get("build_hash", ""), "enterprise": ""})
                elif "enterprise_build" in o and starts:
                    starts[-1]["enterprise"] = "Enterprise" if o["enterprise_build"] else "Team Edition"
        return [
            table("server_starts", "서버 기동 이력",
                  [("time", "기동 시각 (UTC)"), ("version", "버전"), ("build", "빌드 번호"),
                   ("build_date", "빌드 일자"), ("enterprise", "에디션"), ("build_hash", "빌드 해시")], starts,
                  "mattermost.log 의 'Current version is …' 기록. 서버가 기동될 때마다 남습니다."),
            table("server_log", "서버 로그",
                  [("time", "시각 (UTC)"), ("level", "수준"), ("msg", "내용"), ("caller", "위치"), ("extra", "기타 필드")],
                  lines, "logs/mattermost.log (JSON 줄). 접속 문자열의 비밀번호는 로그에서도 가려져 기록됩니다."),
        ], version


    def postgres(self, root: Path, mm: Path | None, cfg: dict) -> tuple[list[dict], dict, dict]:
        pgdatas = find_pgdata(root)
        if not pgdatas:
            raise FileNotFoundError("PostgreSQL 데이터 디렉터리(PG_VERSION + global/pg_control)를 찾지 못했습니다")
        pgdata = pgdatas[0]
        c = open_cluster(pgdata)
        try:
            return self._postgres(c, root, pgdata, mm, cfg)
        finally:
            c.close()

    def _postgres(self, c, root, pgdata, mm, cfg):
        dbs = c.databases()
        want = db_name_from_dsn(((cfg.get("SqlSettings") or {}).get("DataSource")) or "")
        target = next((d for d in dbs if d["name"] == want and d["has_dir"]), None)
        how = "config.json 의 접속 문자열"
        if target is None:
            best = (-1, None)
            for d in dbs:
                if d.get("is_template") or not d["has_dir"]:
                    continue
                db = c.database(d["oid"])
                rel = db.relation_by_name("public", "posts")
                if rel:
                    n = len(db.rows(rel.oid, {"heap"}))
                    if n > best[0]:
                        best = (n, d)
            target, how = best[1], "posts 테이블 행 수"
        if target is None:
            raise LookupError("Mattermost 테이블(public.posts)이 있는 데이터베이스를 찾지 못했습니다")
        db = c.database(target["oid"])

        ctl = c.info()["control"]
        wal = c.wal_summary()
        info = kv("pg_info", "PostgreSQL 정보", {
            "PostgreSQL 버전": c.pg_version,
            "클러스터 상태 (pg_control)": ctl.get("state_name", ""),
            "데이터 디렉터리": pgdata.relative_to(root).as_posix(),
            "데이터베이스 목록": ", ".join(f"{d['name']}({d['oid']})" for d in dbs),
            "분석 대상 DB": f"{target['name']} (oid {target['oid']}) - {how}로 선택",
            "WAL": (f"레코드 {wal.get('records')}개, CRC 오류 {wal.get('crc_errors')}, "
                    f"시각 {' ~ '.join(wal.get('time_range') or [])}") if wal.get("available") else f"읽지 못함: {wal.get('error')}",
        }, "pg_dump 없이 클러스터 파일(heap)과 WAL 을 직접 해석했습니다 (PostgreSQL Viewer 엔진, 읽기 전용).")

        users, channels, teams = Rows(db, "users"), Rows(db, "channels"), Rows(db, "teams")
        uname = {}
        for r in sorted(users.rows, key=lambda r: r["_state"] == "live"):
            if r.get("id"):
                uname[r["id"]] = r.get("username") or ""
        chan = {}
        for r in sorted(channels.rows, key=lambda r: r["_state"] == "live"):
            if r.get("id"):
                chan[r["id"]] = r
        tname = {r["id"]: r.get("displayname") or r.get("name") for r in teams.rows if r.get("id")}

        U = lambda uid: f"{uname[uid]} ({uid})" if uid in uname else (uid or "")

        def C(cid):
            ch = chan.get(cid)
            if not ch:
                return cid or ""
            if ch.get("type") == "D":
                return f"DM: {', '.join(uname.get(u, u[:8]) for u in (ch.get('name') or '').split('__'))} ({cid})"
            return f"{ch.get('displayname') or ch.get('name')} ({cid})"

        sections = [info]
        counts = {}

        posts = Rows(db, "posts")
        p_rows = []
        for r in posts.rows:
            props = r.get("props") if isinstance(r.get("props"), dict) else {}
            if not props and isinstance(r.get("props"), str):
                try:
                    props = json.loads(r["props"])
                except ValueError:
                    props = {}
            deleteat, editat = r.get("deleteat") or 0, r.get("editat") or 0
            tags = []
            if deleteat > 0 and r.get("originalid"):
                tags.append("편집 전 원본")
            elif deleteat > 0 and props.get("deleteBy"):
                tags.append(f"사용자 삭제 (by {uname.get(props['deleteBy'], props['deleteBy'])})")
            elif deleteat > 0:
                tags.append("삭제")
            if editat > 0:
                tags.append("편집됨")
            if r.get("ispinned"):
                tags.append("고정(Pin)")
            if r.get("rootid"):
                tags.append("스레드 답글")
            p_rows.append({
                "create": fmt_ms(r.get("createat")), "channel": C(r.get("channelid")), "user": U(r.get("userid")),
                "message": r.get("message") or "", "tags": ", ".join(tags), "type": r.get("type") or "",
                "edit": fmt_ms(editat), "delete": fmt_ms(deleteat), "update": fmt_ms(r.get("updateat")),
                "root": r.get("rootid") or "", "original": r.get("originalid") or "",
                "files": display(r.get("fileids")) or "", "props": display(r.get("props")) or "",
                "id": r.get("id") or "", "state": STATE_KO.get(r["_state"], r["_state"]),
                "source": SOURCE_KO.get(r["_source"], r["_source"]), "rid": r["_rid"],
                "_rc": r["_state"] if r["_state"] != "live" else ("softdel" if deleteat > 0 else ""),
            })
        p_rows.sort(key=lambda x: (x["create"], x["state"] != "live"))
        live = [r for r in posts.rows if r["_state"] == "live"]
        counts.update(posts_live=len(live),
                      posts_deleted=sum(1 for r in live if (r.get("deleteat") or 0) > 0),
                      posts_edited=sum(1 for r in live if (r.get("editat") or 0) > 0))
        sections.append(table("posts", "메시지 (posts)", [
            ("create", "작성 시각 (UTC)"), ("channel", "채널"), ("user", "작성자"), ("message", "메시지"),
            ("tags", "분류"), ("type", "유형"), ("edit", "편집 시각"), ("delete", "삭제 시각"),
            ("root", "스레드 루트"), ("original", "원본 id (originalid)"), ("files", "첨부 fileids"),
            ("state", "행 상태"), ("source", "출처"), ("id", "post id"), ("rid", "행 위치"), ("props", "props"),
        ], p_rows,
            "posts 테이블 전체 행. 삭제(deleteat>0)여도 message 는 평문으로 남습니다. "
            "편집하면 원본이 deleteat, originalid 가 채워진 행으로 보존되고, 사용자가 지운 글은 props 에 deleteBy 가 남습니다. "
            "'이전 버전'은 UPDATE 로 바뀌기 전 DB 행입니다(빨강=삭제, 주황=이전 버전, 연한 빨강=Mattermost 삭제 표시).",
            row_class="_rc"))

        u_rows = [{
            "username": r.get("username") or "", "email": r.get("email") or "", "nickname": r.get("nickname") or "",
            "name": " ".join(x for x in (r.get("firstname"), r.get("lastname")) if x),
            "roles": r.get("roles") or "", "create": fmt_ms(r.get("createat")), "update": fmt_ms(r.get("updateat")),
            "delete": fmt_ms(r.get("deleteat")), "lastlogin": fmt_ms(r.get("lastlogin")),
            "pwupdate": fmt_ms(r.get("lastpasswordupdate")), "auth": r.get("authservice") or "",
            "locale": r.get("locale") or "", "id": r.get("id") or "",
            "state": STATE_KO.get(r["_state"], r["_state"]),
            "_rc": r["_state"] if r["_state"] != "live" else ("softdel" if (r.get("deleteat") or 0) > 0 else ""),
        } for r in users.visible()]
        counts["users"] = sum(1 for r in users.rows if r["_state"] == "live")
        sections.append(table("users", "사용자 (users)", [
            ("username", "사용자명"), ("email", "이메일"), ("nickname", "닉네임"), ("name", "이름"),
            ("roles", "권한"), ("create", "생성"), ("update", "수정"), ("delete", "삭제"), ("lastlogin", "마지막 로그인"),
            ("pwupdate", "비밀번호 변경"), ("auth", "인증 방식"), ("locale", "언어"), ("id", "user id"), ("state", "행 상태"),
        ], u_rows, "시각은 모두 UTC. 비밀번호 해시 등 전체 컬럼은 'DB 원본'에서 볼 수 있습니다.", row_class="_rc"))

        c_rows = [{
            "type": CHANNEL_TYPES.get(r.get("type"), r.get("type") or ""), "display": r.get("displayname") or "",
            "name": C(r["id"]) if r.get("type") == "D" else (r.get("name") or ""),
            "team": tname.get(r.get("teamid"), r.get("teamid") or "(없음)"), "creator": U(r.get("creatorid")),
            "create": fmt_ms(r.get("createat")), "delete": fmt_ms(r.get("deleteat")),
            "lastpost": fmt_ms(r.get("lastpostat")), "msgs": r.get("totalmsgcount"),
            "header": r.get("header") or "", "purpose": r.get("purpose") or "", "id": r.get("id") or "",
            "state": STATE_KO.get(r["_state"], r["_state"]),
            "_rc": r["_state"] if r["_state"] != "live" else ("softdel" if (r.get("deleteat") or 0) > 0 else ""),
        } for r in channels.visible()]
        counts["channels"] = sum(1 for r in channels.rows if r["_state"] == "live")
        sections.append(table("channels", "채널 (channels)", [
            ("type", "유형"), ("display", "표시 이름"), ("name", "이름"), ("team", "팀"), ("creator", "만든 사람"),
            ("create", "생성"), ("delete", "삭제"), ("lastpost", "마지막 글"), ("msgs", "메시지 수"),
            ("header", "헤더"), ("purpose", "목적"), ("id", "channel id"), ("state", "행 상태"),
        ], c_rows, "DM 채널은 이름이 '<사용자ID>__<사용자ID>' 이므로 사용자명으로 풀어 보여 줍니다.", row_class="_rc"))

        sections.append(table("teams", "팀 (teams)", [
            ("display", "표시 이름"), ("name", "이름"), ("type", "유형"), ("email", "이메일"),
            ("create", "생성"), ("delete", "삭제"), ("id", "team id"), ("state", "행 상태"),
        ], [{"display": r.get("displayname") or "", "name": r.get("name") or "", "type": r.get("type") or "",
             "email": r.get("email") or "", "create": fmt_ms(r.get("createat")), "delete": fmt_ms(r.get("deleteat")),
             "id": r.get("id") or "", "state": STATE_KO.get(r["_state"], r["_state"])} for r in teams.visible()]))

        fi = Rows(db, "fileinfo")
        data_dir = (mm / "data") if mm else None
        by_path = {}
        f_rows = []
        for r in fi.visible():
            path = r.get("path") or ""
            exists = ""
            if data_dir is not None and path:
                exists = "있음" if (data_dir / path).is_file() else "없음"
                by_path[path] = r
                for extra_p in (r.get("thumbnailpath"), r.get("previewpath")):
                    if extra_p:
                        by_path[extra_p] = r
            f_rows.append({
                "create": fmt_ms(r.get("createat")), "name": r.get("name") or "", "ext": r.get("extension") or "",
                "size": r.get("size"), "mime": r.get("mimetype") or "", "creator": U(r.get("creatorid")),
                "channel": C(r.get("channelid")), "post": r.get("postid") or "", "path": path,
                "thumb": r.get("thumbnailpath") or "", "preview": r.get("previewpath") or "", "on_disk": exists,
                "delete": fmt_ms(r.get("deleteat")), "id": r.get("id") or "",
                "state": STATE_KO.get(r["_state"], r["_state"]),
                "_rc": r["_state"] if r["_state"] != "live" else ("softdel" if (r.get("deleteat") or 0) > 0 else ""),
            })
        f_rows.sort(key=lambda x: x["create"])
        counts["files"] = sum(1 for r in fi.rows if r["_state"] == "live")
        counts["_fileinfo_by_path"] = {p: {"name": r.get("name"), "post": r.get("postid"), "user": U(r.get("creatorid")),
                                           "channel": C(r.get("channelid"))} for p, r in by_path.items()}
        sections.append(table("fileinfo", "첨부 파일 (fileinfo)", [
            ("create", "업로드 시각"), ("name", "파일명"), ("ext", "확장자"), ("size", "크기"), ("mime", "MIME"),
            ("creator", "올린 사람"), ("channel", "채널"), ("post", "post id"), ("on_disk", "디스크 원본"),
            ("path", "경로"), ("thumb", "썸네일"), ("preview", "미리보기"), ("delete", "삭제"), ("id", "file id"),
            ("state", "행 상태"),
        ], f_rows, "fileinfo.path 는 data/ 아래 실제 파일 경로입니다. '디스크 원본'은 업로드한 ZIP 에 그 파일이 있는지입니다.",
            row_class="_rc"))

        s = Rows(db, "sessions")
        s_rows = []
        for r in s.visible():
            props = r.get("props") if isinstance(r.get("props"), dict) else {}
            s_rows.append({
                "user": U(r.get("userid")), "create": fmt_ms(r.get("createat")), "expires": fmt_ms(r.get("expiresat")),
                "last": fmt_ms(r.get("lastactivityat")), "device": r.get("deviceid") or "",
                "platform": props.get("platform", ""), "os": props.get("os", ""), "browser": props.get("browser", ""),
                "roles": r.get("roles") or "", "props": display(r.get("props")) or "", "id": r.get("id") or "",
                "state": STATE_KO.get(r["_state"], r["_state"]), "end": r.get("_xmax_time") or "",
                "_rc": r["_state"] if r["_state"] != "live" else "",
            })
        s_rows.sort(key=lambda x: x["create"])
        sections.append(table("sessions", "세션 (sessions)", [
            ("user", "사용자"), ("create", "생성"), ("expires", "만료"), ("last", "마지막 활동"),
            ("platform", "플랫폼"), ("os", "OS"), ("browser", "브라우저"), ("device", "device id"), ("roles", "권한"),
            ("state", "행 상태"), ("end", "삭제 트랜잭션 시각"), ("id", "session id"), ("props", "props"),
        ], s_rows, "로그인 세션. 삭제된 행은 로그아웃, 만료로 지워진 세션입니다. 클라이언트 쿠키 만료 시각과 세션 만료가 일치합니다.",
            row_class="_rc"))

        a = Rows(db, "audits")
        a_rows = sorted([{
            "time": fmt_ms(r.get("createat")), "user": U(r.get("userid")), "action": r.get("action") or "",
            "extra": r.get("extrainfo") or "", "ip": r.get("ipaddress") or "", "session": r.get("sessionid") or "",
            "state": STATE_KO.get(r["_state"], r["_state"]), "_rc": r["_state"] if r["_state"] != "live" else "",
        } for r in a.visible()], key=lambda x: x["time"])
        sections.append(table("audits", "감사 로그 (audits)", [
            ("time", "시각 (UTC)"), ("user", "사용자"), ("action", "행위(API)"), ("extra", "부가 정보"),
            ("ip", "IP"), ("session", "session id"), ("state", "행 상태"),
        ], a_rows, "사용자 행위 기록 (로그인, 비밀번호 변경 등).", row_class="_rc"))

        rx = Rows(db, "reactions")
        if rx.rel:
            sections.append(table("reactions", "반응 (reactions)", [
                ("create", "시각 (UTC)"), ("user", "사용자"), ("emoji", "이모지"), ("post", "post id"),
                ("delete", "삭제"), ("state", "행 상태"),
            ], sorted([{"create": fmt_ms(r.get("createat")), "user": U(r.get("userid")), "emoji": r.get("emojiname") or "",
                        "post": r.get("postid") or "", "delete": fmt_ms(r.get("deleteat")),
                        "state": STATE_KO.get(r["_state"], r["_state"]),
                        "_rc": r["_state"] if r["_state"] != "live" else ""} for r in rx.visible()],
                      key=lambda x: x["create"]), row_class="_rc"))

        extra = {"pg": {"pgdata": pgdata.relative_to(root).as_posix(), "db_oid": target["oid"], "db_name": target["name"]}}
        return sections, counts, extra


    def data_files(self, mm: Path | None, by_path: dict) -> dict:
        cols = [("kind", "종류"), ("date", "날짜 폴더"), ("channel_id", "channel id"), ("user_id", "user id"),
                ("file_id", "file id"), ("name", "파일명"), ("size", "크기(byte)"), ("linked", "fileinfo 연결"),
                ("path", "경로 (data/ 기준)")]
        d = (mm / "data") if mm else None
        if not d or not d.is_dir():
            return table("data_files", "업로드 파일 (data/)", cols, [], "opt/mattermost/data 폴더가 없습니다.")
        rows = []
        for f in sorted(p for p in d.rglob("*") if p.is_file()):
            rel = f.relative_to(d).as_posix()
            parts = rel.split("/")
            row = {"kind": "", "date": "", "channel_id": "", "user_id": "", "file_id": "", "name": f.name,
                   "size": f.stat().st_size, "linked": "", "path": rel}
            if len(parts) >= 7 and parts[1] == "teams" and parts[3] == "channels" and parts[5] == "users":
                row.update(date=parts[0], channel_id=parts[4], user_id=parts[6],
                           file_id=parts[7] if len(parts) > 8 else "")
                stem = f.stem
                row["kind"] = "썸네일" if stem.endswith("_thumb") else "미리보기" if stem.endswith("_preview") else "첨부 원본"
            elif parts[0] == "users" and len(parts) >= 3:
                row.update(kind="프로필 사진", user_id=parts[1])
            elif parts[0] == "emoji" and len(parts) >= 3:
                row.update(kind="커스텀 이모지", file_id=parts[1])
            else:
                row["kind"] = "기타"
            info = by_path.get(rel)
            if info:
                row["linked"] = f"{info['name']}, {info['user']}, post {info['post']}"
            rows.append(row)
        return table("data_files", "업로드 파일 (data/)", cols, rows,
                     "경로 구조: 날짜/teams/<팀>/channels/<채널ID>/users/<사용자ID>/<파일ID>/<파일명>. "
                     "DM, 팀 없는 채널은 teams/noteam. 이미지는 원본과 함께 _thumb, _preview 가 생성됩니다.")


    FINDINGS_DESC = (
        "분석 결과 표들에서 삭제, 편집, 변조 정황만 모았습니다. 확실 = 기록으로 확인되는 사실, 추정 = 정황(다른 원인도 가능). "
        "점검 항목: 메시지 삭제(사용자/삭제자 기록 없음), 편집 원본, DB 에서 지워진 행, 편집 표시 없이 바뀐 내용(WAL, 이전 버전 대조), "
        "시각 역전, 첨부 DB↔디스크 불일치, 사용자, 채널, 반응, 감사 로그 삭제, psql 기록의 데이터 변경, 정리 명령, 로그보다 앞선 DB 활동. "
        "로그아웃으로 지워진 세션, 내용이 같은 원본 보존 행(고정(Pin) 등 속성 변경)은 정상 동작이라 넣지 않았습니다. 행을 누르고 [근거 행으로 이동]으로 원래 표를 엽니다."
    )

    def findings(self, sections: list[dict]) -> list[dict]:
        S = {s["id"]: s for s in sections}
        rows_of = lambda sid: S[sid]["rows"] if sid in S and S[sid].get("type") == "table" else []
        name = lambda s: split_label(s)[0]
        has = lambda sid: sid in S and S[sid].get("type") == "table"
        out: list[dict] = []
        self.findings_notes = [f"{t} 섹션을 해석하지 못해 점검하지 않았습니다" for sid, t in
                               (("posts", "메시지 (posts)"), ("fileinfo", "첨부 파일 (fileinfo)"), ("audits", "감사 로그 (audits)"))
                               if not has(sid)]

        posts = rows_of("posts")
        live = {r["id"]: r for r in posts if r.get("state") == "live"}
        basis = "메시지 (posts)"

        def tgt(r):
            return f"post {r['id']}, {name(r.get('user'))}, {name(r.get('channel'))}"

        def ref(r):
            return {"section": "posts", "match": {"id": r["id"], "rid": r.get("rid", "")}}

        for r in posts:
            tags, msg = r.get("tags") or "", short(r.get("message"))
            if r.get("state") == "live":
                if "편집 전 원본" in tags:
                    cur = live.get(r.get("original"))
                    if cur and (cur.get("message") or "") == (r.get("message") or ""):
                        continue
                    out.append(finding(CERTAIN, "메시지 편집", r.get("delete"), f"post {r.get('original')}, {name(r.get('user'))}, {name(r.get('channel'))}",
                                       f"편집 전: \"{msg}\" → 현재: \"{short(cur.get('message')) if cur else '(현재 행 없음)'}\". "
                                       f"편집 전 원본이 별도 행(id {r['id']}, originalid)으로 보존돼 있습니다.",
                                       basis, ref(r), "updated"))
                elif "사용자 삭제" in tags:
                    who = re.search(r"by ([^)]*)\)", tags)
                    out.append(finding(CERTAIN, "메시지 삭제 (사용자)", r.get("delete"), tgt(r),
                                       f"{who[1] if who else '사용자'} 가 삭제했습니다 (props.deleteBy). 삭제된 내용: \"{msg}\"",
                                       basis, ref(r), "softdel"))
                elif r.get("delete"):
                    out.append(finding(CERTAIN, "메시지 삭제 (삭제자 기록 없음)", r.get("delete"), tgt(r),
                                       f"deleteat 이 있지만 props.deleteBy 가 없습니다 - 관리자, API, 데이터 보존 정책에 의한 삭제일 수 있습니다. 내용: \"{msg}\"",
                                       basis, ref(r), "softdel"))
                c = parse_utc(r.get("create"))
                inv = [f"{label} {r.get(col)}" for col, label in (("edit", "편집"), ("delete", "삭제"), ("update", "수정"))
                       if c and (v := parse_utc(r.get(col))) and v < c]
                if inv:
                    out.append(finding(INFERRED, "시각 역전", r.get("create"), tgt(r),
                                       f"{', '.join(inv)} 시각이 작성 시각({r.get('create')})보다 앞섭니다 - 정상 앱 동작으로는 생기지 않아 "
                                       "DB 직접 수정을 의심할 수 있습니다 (서버 시계 조정으로도 생길 수 있음).", basis, ref(r)))
            elif r.get("_rc") == "deleted":
                carved = r.get("source") == SOURCE_KO["carved"]
                out.append(finding(INFERRED if carved else CERTAIN, "DB 행 삭제", r.get("create"), tgt(r),
                                   f"posts 행이 DB 에서 지워졌습니다 (출처: {r.get('source')}). Mattermost 의 일반 삭제는 행을 남기므로 "
                                   f"영구 삭제 API, 데이터 보존 정책, DB 직접 삭제를 의미합니다. 남은 내용: \"{msg}\""
                                   + (" (페이지 빈 공간에서 복구한 행이라 추정으로 둡니다.)" if carved else ""),
                                   basis, ref(r), "deleted"))

        versions: dict[str, list[dict]] = {}
        for r in posts:
            if r.get("_rc") == "updated" and r.get("state") != "live":
                versions.setdefault(r["id"], []).append(r)
        db_deleted = {r["id"] for r in posts if r.get("_rc") == "deleted"}
        for pid, olds in versions.items():
            cur = live.get(pid)
            if cur is None:
                if pid not in db_deleted:
                    r = olds[0]
                    out.append(finding(CERTAIN, "현재 행 없음", r.get("create"), tgt(r),
                                       f"이 메시지는 이전 버전 {len(olds)}개만 남고 현재 행이 없습니다 - 행이 지워진 뒤 공간이 재사용됐을 수 있습니다. "
                                       f"마지막 내용: \"{short(r.get('message'))}\"", basis, ref(r), "deleted"))
                continue
            changed = [r for r in olds if (r.get("message") or "") != (cur.get("message") or "")]
            if changed and not cur.get("edit"):
                r = changed[0]
                out.append(finding(INFERRED, "편집 표시 없는 내용 변경", cur.get("create"), tgt(cur),
                                   f"이전 버전(출처: {r.get('source')})의 내용 \"{short(r.get('message'))}\" 이 현재 \"{short(cur.get('message'))}\" 와 다르지만 "
                                   "편집 시각(editat)이 비어 있습니다 - 앱 화면 편집이 아닌 DB 직접 수정 가능성.",
                                   basis, ref(r), "updated"))

        for sid, title, label, keys, soft in (
            ("users", "사용자 (users)", lambda r: f"사용자 {r.get('username')} ({r.get('id')})", ("id",), "사용자 비활성화"),
            ("channels", "채널 (channels)", lambda r: f"채널 {r.get('display') or r.get('name')} ({r.get('id')})", ("id",), "채널 보관(삭제)"),
            ("fileinfo", "첨부 파일 (fileinfo)", lambda r: f"첨부 {r.get('name')} ({r.get('id')}), {name(r.get('creator'))}", ("id",), "첨부 삭제"),
            ("reactions", "반응 (reactions)", lambda r: f"반응 :{r.get('emoji')}:, {name(r.get('user'))}, post {r.get('post')}",
             ("post", "user", "emoji", "create"), "반응 삭제"),
            ("audits", "감사 로그 (audits)", lambda r: f"감사 로그 {r.get('action')}, {name(r.get('user'))}", ("time", "action", "session"), ""),
        ):
            for r in rows_of(sid):
                m = {k: r.get(k) for k in (*keys, "state")}
                if r.get("_rc") == "deleted":
                    extra = (" 감사 로그는 앱이 지우지 않으므로 의도적 삭제 정황입니다." if sid == "audits" else "")
                    out.append(finding(CERTAIN, "DB 행 삭제", r.get("delete") or r.get("create") or r.get("time"), label(r),
                                       f"{sid} 행이 DB 에서 지워졌습니다.{extra}", title, {"section": sid, "match": m}, "deleted"))
                elif soft and (r.get("_rc") == "softdel" or (sid == "reactions" and r.get("delete"))):
                    out.append(finding(CERTAIN, soft, r.get("delete"), label(r), "deleteat 이 기록돼 있습니다 (행은 남아 있음). 앱의 정상 기능(반응 취소, 계정 비활성화, 채널 보관 등)으로도 생깁니다.",
                                       title, {"section": sid, "match": m}, "softdel"))
            if sid == "fileinfo" and rows_of("data_files"):
                for r in rows_of(sid):
                    if r.get("on_disk") == "없음":
                        out.append(finding(INFERRED, "첨부 원본 없음", r.get("create"), label(r),
                                           f"fileinfo 에 기록된 파일(data/{r.get('path')})이 업로드한 증거에 없습니다 - 디스크에서 지워졌거나 수집 범위에서 빠졌습니다.",
                                           title, {"section": sid, "match": {"id": r.get("id"), "state": r.get("state")}}, "deleted"))

        for r in (rows_of("data_files") if has("fileinfo") else []):
            if r.get("kind") == "첨부 원본" and not r.get("linked"):
                out.append(finding(INFERRED, "DB 기록 없는 업로드 파일", "", f"파일 {r.get('name')}, data/{r.get('path')}",
                                   "data/ 에는 첨부 원본이 있지만 연결된 fileinfo 행이 없습니다 - fileinfo 행 삭제 또는 다른 DB 의 파일일 수 있습니다.",
                                   "업로드 파일 (data/)", {"section": "data_files", "match": {"path": r.get("path")}}))

        for r in rows_of("psql_history"):
            cmd = r.get("command") or ""
            if PSQL_RISK.search(cmd):
                masked = PSQL_SECRET.sub(lambda m: m[1] + "'****'", cmd)
                out.append(finding(INFERRED, "DB 직접 조작 명령", "", f"{r.get('file')} {r.get('line')}번째 줄",
                                   f"\"{short(masked, 160)}\" - psql 로 데이터를 바꾸거나(DELETE, UPDATE, TRUNCATE, DROP) 삭제 흔적을 정리(VACUUM)하는 명령입니다. "
                                   "시각 기록은 없습니다.", "psql 명령 기록", {"section": "psql_history", "match": {"file": r.get("file"), "line": r.get("line")}}))

        logs = sorted((t, r["time"]) for r in rows_of("server_log") if (t := parse_utc(r.get("time"))))
        if logs:
            first = logs[0][1]
            before = sorted((t, r.get("create")) for r in live.values() if (t := parse_utc(r.get("create"))) and t < logs[0][0])
            if before:
                out.append(finding(INFERRED, "로그 앞부분 없음", first, "서버 로그 (logs/*.log)",
                                   f"서버 로그는 {first} 부터 남아 있지만 그 전에 작성된 메시지가 {len(before)}건 있습니다 ({before[0][1]} ~ {before[-1][1]}). "
                                   "로그가 지워졌거나 회전(용량 초과로 교체)된 것일 수 있습니다.",
                                   "서버 로그, 메시지 (posts)", {"section": "server_log", "match": {"time": first}}))
        return out


    def psql_history(self, root: Path) -> dict | None:
        files = [p for p in root.rglob(".psql_history") if p.is_file()]
        if not files:
            return None
        rows = []
        for f in files:
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if line.strip():
                    rows.append({"file": f.relative_to(root).as_posix(), "line": i, "command": line})
        return table("psql_history", "psql 명령 기록", [("line", "줄"), ("command", "명령"), ("file", "파일")], rows,
                     "PostgreSQL 관리 계정의 psql 명령 기록 (.psql_history). 시각 정보는 없습니다.")

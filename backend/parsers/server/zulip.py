from __future__ import annotations

import ast
import base64
import configparser
import email
import email.policy
import hashlib
import json
import re
import zlib
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from ...pgaccess import display, find_pgdata
from ...vendor.postgresql_viewer.engine.postgres import open_cluster
from ..base import (CERTAIN, INFERRED, BaseParser, error_section, finding, fmt_dt, fmt_ms, kv, parse_utc, short,
                    split_label, table)
from .mattermost import SOURCE_KO, STATE_KO


ROLES = {100: "조직 소유자", 200: "관리자", 300: "모더레이터", 400: "멤버", 600: "게스트"}
BOT_TYPES = {1: "일반 봇", 2: "수신 웹훅 봇", 3: "발신 웹훅 봇", 4: "내장 봇"}
RECIPIENT_TYPES = {1: "개인(구버전)", 2: "채널", 3: "DM 그룹"}
ORG_TYPES = {0: "미지정", 10: "Business", 20: "오픈소스", 30: "교육(비영리)", 35: "교육(영리)", 40: "연구",
             50: "이벤트", 60: "비영리", 70: "정부", 80: "정치 단체", 90: "커뮤니티", 100: "개인", 1000: "기타"}
ARCHIVE_TYPES = {1: "보존 정책에 따른 자동 보관", 2: "수동 삭제 (메시지 삭제)"}
MESSAGE_TYPES = {1: "", 2: "토픽 해결 알림"}
DM_TOPIC = "\x07"

AUDIT_EVENTS = {
    101: "사용자 생성", 102: "사용자 활성화", 103: "사용자 비활성화", 104: "사용자 재활성화", 105: "역할 변경",
    106: "사용자 삭제", 107: "사용자 삭제(메시지 보존)", 108: "특수 권한 변경", 120: "소프트 활성화",
    121: "소프트 비활성화", 122: "비밀번호 변경", 123: "아바타 변경", 124: "이름 변경", 125: "이메일 변경",
    126: "약관 버전 변경", 127: "API 키 변경", 128: "봇 소유자 변경", 129: "기본 발신 채널 변경",
    130: "기본 등록 채널 변경", 131: "기본 전체 공개 채널 변경", 132: "사용자 설정 변경", 133: "다이제스트 메일 생성",
    134: "가져온 스텁 여부 변경", 135: "가입일 변경",
    201: "조직 비활성화", 202: "조직 재활성화", 203: "조직 데이터 삭제(scrub)", 204: "요금제 변경",
    205: "로고 변경", 206: "조직 내보내기", 207: "조직 설정 변경", 208: "아이콘 변경", 214: "서브도메인 변경",
    215: "조직 생성", 216: "기본 사용자 설정 변경", 217: "조직 유형 변경", 218: "도메인 추가", 219: "도메인 변경",
    220: "도메인 삭제", 226: "커스텀 이모지 추가", 227: "커스텀 이모지 삭제", 229: "조직 가져오기",
    230: "내보내기 삭제",
    301: "구독 생성", 302: "구독 활성화", 303: "구독 해제", 304: "구독 속성 변경", 350: "사용자 음소거",
    351: "사용자 음소거 해제",
    601: "채널 생성", 602: "채널 보관(비활성화)", 603: "채널 이름 변경", 604: "채널 재활성화",
    605: "채널 보존 기간 변경", 607: "채널 속성 변경", 608: "채널 권한 그룹 변경", 609: "채널 폴더 변경",
    701: "사용자 그룹 생성", 702: "사용자 그룹 삭제", 703: "그룹 멤버 추가", 704: "그룹 멤버 제거",
    705: "하위 그룹 추가", 706: "하위 그룹 제거", 707: "상위 그룹 추가", 708: "상위 그룹 제거",
    720: "그룹 이름 변경", 721: "그룹 설명 변경", 722: "그룹 권한 설정 변경", 723: "그룹 비활성화",
    724: "그룹 재활성화", 725: "사용자 수 변경", 800: "저장된 스니펫 생성", 810: "사용자 지정 메일 발송",
    850: "내비게이션 뷰 생성", 851: "내비게이션 뷰 변경", 852: "내비게이션 뷰 삭제",
    901: "채널 폴더 생성", 902: "채널 폴더 이름 변경", 903: "채널 폴더 설명 변경", 904: "채널 폴더 보관",
    905: "채널 폴더 보관 해제", 1001: "초대 취소",
}

SECRET_PURPOSE = {
    "secret_key": "Django 세션, 서명 (세션 쿠키 서명 검증에 쓰임)",
    "avatar_salt": "아바타 경로 해시 솔트",
    "rabbitmq_password": "RabbitMQ 인증",
    "shared_secret": "내부 서비스(Tornado 등) 인증",
    "camo_key": "이미지 프록시(camo) 서명",
    "memcached_password": "memcached 인증",
    "redis_password": "Redis 인증",
    "zulip_org_key": "푸시 알림 서비스 등록 키",
    "zulip_org_id": "푸시 알림 서비스 조직 식별자",
    "postgres_password": "PostgreSQL 접속",
    "email_password": "SMTP 발송 계정",
}

REQUEST_MEANINGS = [
    ("POST", r"^/(json|api/v1)/messages$", "메시지 전송", "sent"),
    ("PATCH", r"^/(json|api/v1)/messages/(\d+)$", "메시지 편집, 이동 (id {2})", "updated"),
    ("DELETE", r"^/(json|api/v1)/messages/(\d+)$", "메시지 삭제 (id {2})", "deleted"),
    ("POST", r"^/(json|api/v1)/messages/(\d+)/reactions$", "반응 추가 (메시지 id {2})", ""),
    ("DELETE", r"^/(json|api/v1)/messages/(\d+)/reactions$", "반응 삭제 (메시지 id {2})", ""),
    ("POST", r"^/(json|api/v1)/messages/flags", "읽음, 별표 표시", ""),
    ("GET", r"^/(json|api/v1)/messages", "메시지 조회", ""),
    ("POST", r"^/accounts/login/$", "로그인 (302 = 성공)", "login"),
    ("GET", r"^/accounts/login/subdomain/", "가입 직후 자동 로그인", "login"),
    ("", r"^/accounts/logout", "로그아웃", "login"),
    ("POST", r"^/accounts/register/$", "계정 등록", "login"),
    ("POST", r"^/realm/register/$", "조직 등록", "login"),
    ("", r"^/new/", "조직 생성 링크 열기", "login"),
    ("", r"^/accounts/do_confirm/", "확인 링크 열기", ""),
    ("", r"^/join/", "초대 링크로 가입", "login"),
    ("", r"^/accounts/send_confirm/", "가입 확인 메일 발송 화면", ""),
    ("POST", r"^/json/invites/multiuse", "초대 링크 생성", ""),
    ("POST", r"^/json/invites$", "초대 메일 발송", ""),
    ("POST", r"^/(json|api/v1)/users/me/subscriptions$", "채널 구독 (또는 생성)", ""),
    ("DELETE", r"^/(json|api/v1)/users/me/subscriptions$", "채널 구독 해제", ""),
    ("PATCH", r"^/(json|api/v1)/streams/(\d+)$", "채널 설정 변경 (id {2})", "updated"),
    ("DELETE", r"^/(json|api/v1)/streams/(\d+)$", "채널 보관 (id {2})", "deleted"),
    ("DELETE", r"^/(json|api/v1)/users/(\d+)$", "사용자 비활성화 (id {2})", "deleted"),
    ("", r"^/(json|api/v1)/users/me/\d+/topics$", "채널 토픽 목록 조회", ""),
    ("POST", r"^/(json|api/v1)/typing$", "입력 중 표시", ""),
    ("POST", r"^/(json|api/v1)/users/me/presence$", "접속 상태 갱신", ""),
    ("", r"^/(json|api/v1)/drafts", "초안 동기화", ""),
    ("GET", r"^/user_uploads/thumbnail/", "첨부 썸네일 열람", ""),
    ("GET", r"^/user_uploads/", "첨부 파일 열람, 다운로드", ""),
    ("POST", r"^/(json|api/v1)/user_uploads", "파일 업로드", ""),
    ("POST", r"^/api/internal/tusd$", "파일 업로드 처리 (tusd 훅)", ""),
    ("GET", r"^/user_avatars/", "아바타 이미지", ""),
    ("GET", r"^/api/v1/server_settings$", "서버 정보 조회 (앱이 서버 추가할 때)", ""),
    ("GET", r"^/login/$", "로그인 화면", ""),
    ("", r"^/(json|api/v1)/users/me/onboarding_steps", "안내 단계 기록", ""),
    ("", r"^/health$", "상태 점검 (내부)", ""),
    ("", r"^/(json|api/v1)/(events|register)", "이벤트 큐", ""),
]
REQ_RE = re.compile(
    r"^(?P<t>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+(?P<lv>\w+)\s+\[(?P<tag>zr|zulip\.slow_queries)\]\s+(?P<ip>\S+)\s+"
    r"(?P<m>[A-Z]+)\s+(?P<st>\d{3})\s+(?P<dur>\S+)\s+(?P<rest>.*?)\s+\((?P<user>[^()@\s]*)@(?P<sub>[^\s()]*) via (?P<client>[^()]*)\)\s*$")
LOG_TS = [
    (re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)[.,](\d{3})\d*:?\s+(.*)$"), "%Y-%m-%d %H:%M:%S"),
    (re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)\.(\d{3})\d*\s+(.*)$"), "%Y/%m/%d %H:%M:%S"),
]
LEVEL_RE = re.compile(r"^(DEBUG|INFO|WARNING|WARN|ERROR|ERR|CRITICAL)\s+(.*)$")


def _to_utc_text(dt: datetime | None) -> str:
    return fmt_dt(dt) if dt else ""


def T(v) -> str:
    if isinstance(v, datetime):
        return fmt_dt(v)
    if v is None:
        return ""
    s = str(v)
    if re.match(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d", s):
        try:
            return fmt_dt(datetime.fromisoformat(s))
        except ValueError:
            pass
    return s


def find_dir(root: Path, *names: str) -> Path | None:
    want = list(names)
    best = None
    for p in root.rglob(want[-1]):
        if p.is_dir() and list(p.parts[-len(want):]) == want:
            if best is None or len(p.parts) < len(best.parts):
                best = p
    return best


def evidence_path(root: Path, linux_path) -> Path | None:
    if not isinstance(linux_path, str) or not linux_path.startswith("/"):
        return None
    parts = [p for p in linux_path.split("/") if p]
    if any(p in (".", "..") or ":" in p or "\\" in p for p in parts) or not parts:
        return None
    cand = root.joinpath(*parts)
    try:
        if not cand.resolve().is_relative_to(root.resolve()):
            return None
    except OSError:
        return None
    return cand if cand.is_dir() else None


def mask(v: str) -> str:
    return (v[:4] + "…" + f" ({len(v)}자)") if len(v) > 8 else "****"


class Rows:
    def __init__(self, db, name: str):
        self.rel = None
        for schema in ("zulip", "public"):
            self.rel = db.relation_by_name(schema, name)
            if self.rel:
                break
        if self.rel is None:
            self.rel = next((r for r in db.relations.values() if r.name == name and r.kind == "r"), None)
        self.cols = [a.name for a in self.rel.attrs] if self.rel else []
        self.rows = []
        if self.rel and self.rel.has_heap:
            for r in db.rows(self.rel.oid):
                rec = dict(zip(self.cols, r["values"]))
                rec.update(_state=r["state"], _source=r["source"], _rid=r["rid"],
                           _xmin_time=r.get("xmin_time") or "", _xmax_time=r.get("xmax_time") or "")
                self.rows.append(rec)

    def visible(self):
        return [r for r in self.rows if r["_state"] in ("live", "deleted")]

    def live(self):
        return [r for r in self.rows if r["_state"] == "live"]

    def by_id(self) -> dict:
        out = {}
        for r in sorted(self.rows, key=lambda r: r["_state"] == "live"):
            if r.get("id") is not None:
                out[r["id"]] = r
        return out


def rc(r: dict) -> str:
    return r["_state"] if r["_state"] != "live" else ""


def state(r: dict) -> str:
    return STATE_KO.get(r["_state"], r["_state"])


class ZulipServerParser(BaseParser):
    mode = "server"
    app = "zulip"
    is_dummy = False

    def parse(self, root: Path, inventory: list[dict]) -> dict:
        sections: list[dict] = []
        ctx: dict = {"root": root, "users": {}, "counts": {}}
        extra: dict = {}

        try:
            self.load_config(root, ctx)
        except Exception as e:
            sections.append(error_section("config_load", "서버 설정", e))

        try:
            sections.append(self.server_info(root, ctx))
        except Exception as e:
            sections.append(error_section("server_info", "서버 정보", e))

        try:
            secs, extra = self.postgres(root, ctx)
            sections += secs
        except Exception as e:
            sections.append(error_section("pg", "PostgreSQL", e))

        for fn, title in ((self.requests, "요청 로그"), (self.auth_log, "인증 기록"), (self.emails, "발송 메일"),
                          (self.uploads, "업로드 파일"), (self.avatars, "아바타 파일"), (self.config_sections, "설정 파일"),
                          (self.other_logs, "서버 로그"), (self.install_log, "설치 기록")):
            try:
                out = fn(root, ctx)
                if out:
                    sections.extend(out if isinstance(out, list) else [out])
            except Exception as e:
                sections.append(error_section(fn.__name__, title, e))

        c = ctx["counts"]
        summary = [
            {"label": "서버 버전", "value": ctx.get("version") or "-"},
            {"label": "메시지 (live)", "value": c.get("messages", "-")},
            {"label": "삭제된 메시지 (보관)", "value": c.get("archived", "-")},
            {"label": "사용자 (사람/봇)", "value": f"{c['humans']}/{c['bots']}" if "humans" in c else "-"},
            {"label": "채널", "value": c.get("streams", "-")},
            {"label": "첨부 파일", "value": c.get("attachments", "-")},
            {"label": "요청 로그", "value": c.get("requests", 0)},
        ]
        return {"summary": summary, "sections": sections, **extra}


    def load_config(self, root: Path, ctx: dict):
        etc = find_dir(root, "etc", "zulip")
        ctx["etc"] = etc
        settings, conf, secrets = {}, None, {}
        if etc and (etc / "settings.py").is_file():
            settings = self._settings_py((etc / "settings.py").read_text(encoding="utf-8", errors="replace"))
        if etc and (etc / "zulip.conf").is_file():
            conf = configparser.ConfigParser(interpolation=None)
            conf.read_string((etc / "zulip.conf").read_text(encoding="utf-8", errors="replace"))
        if etc and (etc / "zulip-secrets.conf").is_file():
            sc = configparser.ConfigParser(interpolation=None)
            sc.read_string((etc / "zulip-secrets.conf").read_text(encoding="utf-8", errors="replace"))
            if sc.has_section("secrets"):
                secrets = dict(sc.items("secrets"))
        ctx.update(settings=settings, conf=conf, secrets=secrets)

        up = evidence_path(root, (settings.get("LOCAL_UPLOADS_DIR") or {}).get("value"))
        ctx["uploads"] = up or find_dir(root, "zulip", "uploads")
        ctx["logs"] = find_dir(root, "log", "zulip")

        dep = find_dir(root, "zulip", "deployments")
        ctx["deployments"] = dep
        version, vsrc = "", ""
        if dep:
            for vp in sorted(dep.glob("*/version.py")):
                m = re.search(r'^ZULIP_VERSION\s*=\s*"([^"]+)"', vp.read_text(encoding="utf-8", errors="replace"), re.M)
                if m:
                    version, vsrc = m[1], vp.relative_to(root).as_posix()
            if not version:
                for vp in sorted(dep.glob("*/version")):
                    version, vsrc = vp.read_text(encoding="utf-8", errors="replace").strip(), vp.relative_to(root).as_posix()
        if not version and ctx["logs"] and (ctx["logs"] / "install.log").is_file():
            m = re.search(r"zulip-server-(\d+\.\d+(?:\.\d+)?)", (ctx["logs"] / "install.log").read_text(encoding="utf-8", errors="replace"))
            if m:
                version, vsrc = m[1], "install.log"
        ctx["version"], ctx["version_src"] = version, vsrc

    @staticmethod
    def _settings_py(src: str) -> dict:
        out = {}
        try:
            tree = ast.parse(src)
        except SyntaxError:
            for m in re.finditer(r"^([A-Z][A-Z0-9_]*)\s*(?::[^=]+)?=\s*(.+)$", src, re.M):
                out[m[1]] = {"value": m[2].strip(), "line": src[:m.start()].count("\n") + 1}
            return out
        for node in tree.body:
            targets = []
            if isinstance(node, ast.Assign):
                targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                targets = [node.target.id]
            for name in targets:
                try:
                    val = ast.literal_eval(node.value)
                except (ValueError, SyntaxError, TypeError):
                    val = ast.get_source_segment(src, node.value) or ""
                out[name] = {"value": val, "line": node.lineno}
        return out

    def server_info(self, root: Path, ctx: dict) -> dict:
        s = ctx.get("settings") or {}
        conf = ctx.get("conf")
        sv = lambda k: s.get(k, {}).get("value", "")
        cv = lambda sec, k: conf.get(sec, k, fallback="") if conf else ""
        dep = ctx.get("deployments")
        cur = ""
        if dep and (dep / "current").exists():
            p = dep / "current"
            cur = p.read_text(encoding="utf-8", errors="replace").strip("\x00 \r\n\t") if p.is_file() and p.stat().st_size < 4096 else "(폴더)"
        backends = sv("AUTHENTICATION_BACKENDS")
        items = {
            "Zulip 버전": f"{ctx.get('version') or '-'}" + (f"  (근거: {ctx['version_src']})" if ctx.get("version_src") else ""),
            "현재 배포 (deployments/current)": cur,
            "배포 폴더": ", ".join(p.name for p in sorted(dep.iterdir()) if p.is_dir()) if dep else "",
            "설치 방식 (zulip.conf puppet_classes)": cv("machine", "puppet_classes"),
            "배포 유형 (deploy_type)": cv("machine", "deploy_type"),
            "PostgreSQL 버전 (zulip.conf)": cv("postgresql", "version"),
            "서버 주소 (EXTERNAL_HOST)": sv("EXTERNAL_HOST"),
            "관리자 메일 (ZULIP_ADMINISTRATOR)": sv("ZULIP_ADMINISTRATOR"),
            "업로드 경로 (LOCAL_UPLOADS_DIR)": sv("LOCAL_UPLOADS_DIR"),
            "인증 백엔드 (AUTHENTICATION_BACKENDS)": ", ".join(backends) if isinstance(backends, (list, tuple)) else str(backends),
            "메일 백엔드 (EMAIL_BACKEND)": sv("EMAIL_BACKEND"),
            "메일 파일 저장 (EMAIL_FILE_PATH)": sv("EMAIL_FILE_PATH"),
            "푸시 알림 서비스 (ZULIP_SERVICE_PUSH_NOTIFICATIONS)": sv("ZULIP_SERVICE_PUSH_NOTIFICATIONS"),
        }
        return kv("server_info", "서버 정보", {k: str(v) for k, v in items.items() if v not in ("", None)},
                  "/etc/zulip/settings.py, zulip.conf, deployments/<타임스탬프>/version.py. "
                  "EMAIL_BACKEND 가 filebased 이면 발송 메일 원문이 EMAIL_FILE_PATH 에 파일로 남습니다.")

    def config_sections(self, root: Path, ctx: dict) -> list[dict]:
        out = []
        s = ctx.get("settings") or {}
        if s:
            rows = [{"name": k, "value": v["value"] if isinstance(v["value"], str) else json.dumps(v["value"], ensure_ascii=False, default=str),
                     "line": v["line"]} for k, v in s.items()]
            out.append(table("settings_py", "settings.py", [("line", "줄"), ("name", "설정"), ("value", "값")], rows,
                             "/etc/zulip/settings.py 의 최상위 설정 (파일을 실행하지 않고 구문만 해석). 주석 처리된 기본값은 제외됩니다."))
        conf = ctx.get("conf")
        if conf:
            rows = [{"section": sec, "key": k, "value": v} for sec in conf.sections() for k, v in conf.items(sec)]
            out.append(table("zulip_conf", "zulip.conf", [("section", "섹션"), ("key", "키"), ("value", "값")], rows,
                             "/etc/zulip/zulip.conf - 설치 방식(puppet_classes), PostgreSQL 버전 등."))
        sec = ctx.get("secrets") or {}
        if sec:
            rows = [{"key": k, "length": len(v), "purpose": SECRET_PURPOSE.get(k, ""), "value": mask(v)} for k, v in sec.items()]
            out.append(table("secrets", "서버 시크릿 (zulip-secrets.conf)",
                             [("key", "키"), ("length", "길이"), ("purpose", "용도"), ("value", "값 (일부)")], rows,
                             f"/etc/zulip/zulip-secrets.conf 의 [secrets] {len(rows)}종. 평문으로 저장됩니다. 화면에는 앞 4자만 보이며, "
                             "원문은 '파일 목록'의 원본 파일에 있습니다. secret_key 는 세션 쿠키 서명, avatar_salt 는 아바타 경로 계산에 쓰입니다."))
        return out


    def postgres(self, root: Path, ctx: dict) -> tuple[list[dict], dict]:
        pgdatas = find_pgdata(root)
        if not pgdatas:
            raise FileNotFoundError("PostgreSQL 데이터 디렉터리(PG_VERSION + global/pg_control)를 찾지 못했습니다. "
                                    "/var/lib/postgresql/<버전>/main 을 수집해 ZIP 에 넣어 주세요.")
        pgdata = pgdatas[0]
        c = open_cluster(pgdata)
        try:
            return self._postgres(c, root, pgdata, ctx)
        finally:
            c.close()

    def _postgres(self, c, root, pgdata, ctx):
        dbs = c.databases()
        target, how = next((d for d in dbs if d["name"] == "zulip" and d["has_dir"]), None), "DB 이름 zulip"
        if target is None:
            best = (-1, None)
            for d in dbs:
                if d.get("is_template") or not d["has_dir"]:
                    continue
                r = Rows(c.database(d["oid"]), "zerver_message")
                if r.rel and len(r.rows) > best[0]:
                    best = (len(r.rows), d)
            target, how = best[1], "zerver_message 행 수"
        if target is None:
            raise LookupError("Zulip 테이블(zerver_message)이 있는 데이터베이스를 찾지 못했습니다")
        db = c.database(target["oid"])

        wal = c.wal_summary()
        sections = [kv("pg_info", "PostgreSQL 정보", {
            "PostgreSQL 버전": c.pg_version,
            "클러스터 상태 (pg_control)": c.info()["control"].get("state_name", ""),
            "데이터 디렉터리": pgdata.relative_to(root).as_posix(),
            "데이터베이스 목록": ", ".join(f"{d['name']}({d['oid']})" for d in dbs),
            "분석 대상 DB": f"{target['name']} (oid {target['oid']}) - {how}로 선택",
            "WAL": (f"읽지 못함: {wal.get('error')}" if not wal.get("available")
                    else (f"레코드 {wal.get('records')}개, CRC 오류 {wal.get('crc_errors')}, 시각 {' ~ '.join(wal.get('time_range') or [])}"
                          if wal.get("records") else
                          f"해석된 레코드 없음 - 엔진은 PostgreSQL 17 WAL 형식만 해석합니다 (이 클러스터는 {c.pg_version}). "
                          "행 복원은 heap 파일 기준입니다.")),
        }, "pg_dump 없이 클러스터 파일(heap)을 직접 해석했습니다 (PostgreSQL Viewer 엔진, 읽기 전용). "
           "WAL 해석은 엔진이 지원하는 버전(PostgreSQL 17)에서만 됩니다.")]

        counts = ctx["counts"]
        realms = Rows(db, "zerver_realm").by_id()
        users_t = Rows(db, "zerver_userprofile")
        users = users_t.by_id()
        streams_t = Rows(db, "zerver_stream")
        streams = streams_t.by_id()
        recips_t = Rows(db, "zerver_recipient")
        recips = recips_t.by_id()
        subs_t = Rows(db, "zerver_subscription")
        clients = {r["id"]: r.get("name") or "" for r in Rows(db, "zerver_client").rows if r.get("id") is not None}
        ctx["users"] = {uid: u for uid, u in users.items()}

        def U(uid):
            u = users.get(uid)
            return f"{u.get('full_name') or ''} <{u.get('delivery_email') or u.get('email') or ''}> (id {uid})" if u else ("" if uid is None else f"id {uid}")

        members: dict[int, list[int]] = {}
        active: dict[int, list[int]] = {}
        for s in subs_t.live():
            members.setdefault(s.get("recipient_id"), []).append(s.get("user_profile_id"))
            if s.get("active") is not False:
                active.setdefault(s.get("recipient_id"), []).append(s.get("user_profile_id"))

        def is_dm(rid) -> bool:
            return (recips.get(rid) or {}).get("type") in (1, 3)

        def R(rid):
            r = recips.get(rid)
            if not r:
                return "" if rid is None else f"recipient {rid}"
            if r.get("type") == 2:
                st = streams.get(r.get("type_id"))
                return f"#{st.get('name')} (채널 id {r.get('type_id')})" if st else f"채널 id {r.get('type_id')}"
            if r.get("type") == 3:
                names = [(users.get(u) or {}).get("full_name") or f"id {u}" for u in sorted(members.get(rid, []))]
                return f"DM: {', '.join(names)} (그룹 {r.get('type_id')})"
            if r.get("type") == 1:
                return f"DM → {U(r.get('type_id'))}"
            return f"recipient {rid}"

        try:
            att_link = {}
            for r in Rows(db, "zerver_attachment_messages").live():
                att_link.setdefault(r.get("message_id"), []).append(r.get("attachment_id"))
            msgs = Rows(db, "zerver_message")
            arch = Rows(db, "zerver_archivedmessage")
            trans = Rows(db, "zerver_archivetransaction").by_id()

            def msg_row(r, archived=False):
                topic = r.get("subject") or ""
                tags = []
                if archived:
                    t = trans.get(r.get("archive_transaction_id")) or {}
                    tags.append(f"삭제됨 - {ARCHIVE_TYPES.get(t.get('type'), t.get('type'))} ({T(t.get('timestamp'))})")
                    if t.get("restored"):
                        tags.append(f"복원됨 {T(t.get('restored_timestamp'))}")
                if r.get("last_edit_time"):
                    tags.append("편집됨")
                if MESSAGE_TYPES.get(r.get("type")):
                    tags.append(MESSAGE_TYPES[r["type"]])
                if r.get("has_attachment"):
                    tags.append("첨부")
                return {
                    "time": T(r.get("date_sent")), "conv": R(r.get("recipient_id")),
                    "topic": "(DM)" if topic == DM_TOPIC or is_dm(r.get("recipient_id"))
                             else (topic if topic else "(빈 토픽 = general chat)"),
                    "sender": U(r.get("sender_id")), "content": r.get("content") or "", "tags": ", ".join(tags),
                    "edit": T(r.get("last_edit_time")), "client": clients.get(r.get("sending_client_id"), r.get("sending_client_id") or ""),
                    "attachments": ", ".join(str(a) for a in att_link.get(r.get("id"), [])),
                    "id": r.get("id"), "table": "zerver_archivedmessage" if archived else "zerver_message",
                    "state": state(r), "source": SOURCE_KO.get(r["_source"], r["_source"]), "rid": r["_rid"],
                    "_rc": "softdel" if archived and r["_state"] == "live" else rc(r),
                }

            m_rows = [msg_row(r) for r in msgs.rows] + [msg_row(r, True) for r in arch.rows]
            m_rows.sort(key=lambda x: (x["time"], x["state"] != "live"))
            counts["messages"] = len(msgs.live())
            counts["archived"] = len(arch.live())
            sections.append(table("messages", "메시지", [
                ("time", "보낸 시각 (UTC)"), ("conv", "대화방"), ("topic", "토픽"), ("sender", "보낸 사람"),
                ("content", "내용 (Markdown 원문)"), ("tags", "분류"), ("edit", "마지막 편집"), ("client", "보낸 클라이언트"),
                ("attachments", "첨부 id"), ("id", "message id"), ("table", "테이블"), ("state", "행 상태"),
                ("source", "출처"), ("rid", "행 위치"),
            ], m_rows,
                "zerver_message(현재 메시지) + zerver_archivedmessage(사용자가 삭제한 메시지). Zulip 은 메시지를 지우면 보관 테이블로 옮기므로 "
                "본문이 그대로 남습니다 (연한 빨강). 편집 전 내용은 '편집 이력', UPDATE 이전 DB 행은 '이전 버전'(주황), "
                "DB 에서 지워진 행은 빨강입니다. DM 의 토픽은 내부적으로 BEL(\\x07) 문자입니다.", row_class="_rc"))
        except Exception as e:
            sections.append(error_section('messages', '메시지 (zerver_message) + 보관된(삭제) 메시지 (zerver_archivedmessage)', e))

        try:
            e_rows = []
            for r in msgs.rows + arch.rows:
                if r["_state"] not in ("live", "deleted") or not r.get("edit_history"):
                    continue
                try:
                    hist = json.loads(r["edit_history"])
                except (TypeError, ValueError):
                    continue
                for h in hist if isinstance(hist, list) else []:
                    if not isinstance(h, dict):
                        continue
                    ts = h.get("timestamp")
                    e_rows.append({
                        "time": fmt_ms(ts * 1000) if isinstance(ts, (int, float)) and ts == ts else "",
                        "id": r.get("id"), "user": U(h.get("user_id")),
                        "prev_content": h.get("prev_content", ""), "prev_topic": h.get("prev_topic", ""),
                        "topic": h.get("topic", ""), "prev_stream": h.get("prev_stream", ""), "stream": h.get("stream", ""),
                        "current": r.get("content") or "",
                    })
            e_rows.sort(key=lambda x: x["time"])
            sections.append(table("edit_history", "편집 이력", [
                ("time", "편집 시각 (UTC)"), ("id", "message id"), ("user", "편집한 사람"), ("prev_content", "편집 전 내용"),
                ("current", "현재 내용"), ("prev_topic", "이전 토픽"), ("topic", "바뀐 토픽"), ("prev_stream", "이전 채널 id"),
                ("stream", "바뀐 채널 id"),
            ], e_rows, "zerver_message.edit_history (JSON). 내용 편집은 prev_content, 토픽, 채널 이동은 prev_topic, prev_stream 으로 남습니다."))
        except Exception as e:
            sections.append(error_section('edit_history', '편집 이력 (edit_history JSON)', e))

        try:
            u_rows = []
            for r in users_t.visible():
                pw = r.get("password") or ""
                u_rows.append({
                    "name": r.get("full_name") or "", "email": r.get("delivery_email") or "", "email_internal": r.get("email") or "",
                    "role": ROLES.get(r.get("role"), r.get("role")),
                    "kind": BOT_TYPES.get(r.get("bot_type"), "봇") if r.get("is_bot") else "사람",
                    "bot_owner": U(r.get("bot_owner_id")) if r.get("bot_owner_id") else "",
                    "realm": f"{(realms.get(r.get('realm_id')) or {}).get('name') or ''} (id {r.get('realm_id')})",
                    "active": "활성" if r.get("is_active") else "비활성",
                    "joined": T(r.get("date_joined")), "last_login": T(r.get("last_login")),
                    "pw_kind": "로그인 불가 표시 (!)" if pw.startswith("!") else (pw.split("$")[0] if "$" in pw else ("없음" if not pw else "기타")),
                    "password": pw, "api_key": r.get("api_key") or "", "tz": r.get("timezone") or "",
                    "avatar": f"{r.get('avatar_source') or ''} v{r.get('avatar_version') or ''}",
                    "id": r.get("id"), "state": state(r), "_rc": rc(r) or ("softdel" if not r.get("is_active") else ""),
                })
            u_rows.sort(key=lambda x: (x["id"] if isinstance(x["id"], int) else 0))
            live_u = users_t.live()
            counts["humans"] = sum(1 for r in live_u if not r.get("is_bot"))
            counts["bots"] = sum(1 for r in live_u if r.get("is_bot"))
            sections.append(table("users", "사용자 (zerver_userprofile)", [
                ("id", "user id"), ("name", "이름"), ("email", "이메일 (delivery_email)"), ("role", "역할"), ("kind", "종류"),
                ("realm", "조직"), ("active", "상태"), ("joined", "가입 (UTC)"), ("last_login", "마지막 로그인 (UTC)"),
                ("pw_kind", "비밀번호 형식"), ("password", "비밀번호 해시"), ("api_key", "API 키"), ("tz", "시간대"),
                ("bot_owner", "봇 소유자"), ("email_internal", "내부 email"), ("avatar", "아바타"), ("state", "행 상태"),
            ], u_rows, "사람 계정의 비밀번호는 argon2 해시로, 시스템 봇은 사용 불가 표시('!' 접두)로 저장됩니다. "
                       "API 키는 평문 32자로 그 자체가 인증 수단이므로 취급에 주의하세요. 요청 로그의 '<id>@…' 는 이 user id 입니다.",
                row_class="_rc"))
        except Exception as e:
            sections.append(error_section('users', '사용자', e))

        try:
            sections.append(table("realms", "조직 (zerver_realm)", [
                ("id", "id"), ("name", "이름"), ("string_id", "서브도메인 (string_id)"), ("org_type", "유형"),
                ("created", "생성 (UTC)"), ("deactivated", "비활성"), ("invite_required", "초대 필요"),
                ("description", "설명"), ("state", "행 상태"),
            ], [{"id": r.get("id"), "name": r.get("name") or "", "string_id": r.get("string_id") or "(빈 값 = 루트 도메인)",
                 "org_type": f"{ORG_TYPES.get(r.get('org_type'), '')} ({r.get('org_type')})", "created": T(r.get("date_created")),
                 "deactivated": r.get("deactivated"), "invite_required": r.get("invite_required"),
                 "description": r.get("description") or "", "state": state(r), "_rc": rc(r)}
                for r in Rows(db, "zerver_realm").visible()],
                "zulipinternal 은 시스템 봇용 내부 조직입니다. 요청 로그의 '@root' 는 서브도메인이 없는 기본 조직을 뜻합니다.", row_class="_rc"))
        except Exception as e:
            sections.append(error_section('realms', '조직', e))

        try:
            s_rows = [{"id": r.get("id"), "name": r.get("name") or "", "kind": "비공개" if r.get("invite_only") else ("웹 공개" if r.get("is_web_public") else "공개"),
                       "creator": U(r.get("creator_id")), "created": T(r.get("date_created")),
                       "deactivated": "보관됨" if r.get("deactivated") else "", "description": r.get("description") or "",
                       "history": r.get("history_public_to_subscribers"), "retention": r.get("message_retention_days"),
                       "subs": len(active.get(r.get("recipient_id"), [])), "recipient": r.get("recipient_id"),
                       "state": state(r), "_rc": rc(r) or ("softdel" if r.get("deactivated") else "")}
                      for r in streams_t.visible()]
            s_rows.sort(key=lambda x: x["id"] or 0)
            counts["streams"] = len(streams_t.live())
            sections.append(table("streams", "채널 (zerver_stream)", [
                ("id", "채널 id"), ("name", "이름"), ("kind", "공개 범위"), ("creator", "만든 사람"), ("created", "생성 (UTC)"),
                ("deactivated", "보관"), ("subs", "구독자 수 (활성)"), ("description", "설명"),
                ("history", "구독 전 기록 공개"), ("retention", "보존 기간(일)"), ("recipient", "recipient id"), ("state", "행 상태"),
            ], s_rows, "클라이언트 breadcrumb 의 #narrow/channel/<id>-<이름> 의 id 가 이 채널 id 입니다.", row_class="_rc"))
        except Exception as e:
            sections.append(error_section('streams', '채널', e))

        try:
            huddles = Rows(db, "zerver_huddle").by_id()
            r_rows = []
            for r in recips_t.visible():
                hd = huddles.get(r.get("type_id")) if r.get("type") == 3 else None
                r_rows.append({"id": r.get("id"), "type": f"{RECIPIENT_TYPES.get(r.get('type'), '')} ({r.get('type')})",
                               "type_id": r.get("type_id"), "label": R(r.get("id")),
                               "members": ", ".join(U(u) for u in sorted(active.get(r.get("id"), []) if r.get("type") == 2 else members.get(r.get("id"), []))),
                               "group_size": (hd or {}).get("group_size", ""), "state": state(r), "_rc": rc(r)})
            sections.append(table("recipients", "대화 상대 (zerver_recipient)", [
                ("id", "recipient id"), ("type", "유형"), ("type_id", "대상 id"), ("label", "대화방"),
                ("members", "참여자 (채널: 활성 구독, DM: 전체)"), ("group_size", "DM 인원"), ("state", "행 상태"),
            ], r_rows, "메시지의 수신 대상. 유형 2 = 채널(대상 id = 채널 id), 3 = DM 그룹(Zulip 12.3 은 1:1 DM 도 3, 대상 id = zerver_huddle id), "
                       "1 = 구버전의 1:1 DM(대상 id = 사용자 id). "
                       "DM 참여자는 해당 recipient 의 구독으로 알 수 있습니다.", row_class="_rc"))
        except Exception as e:
            sections.append(error_section('recipients', '대화 상대 (recipient, DM 그룹)', e))

        try:
            sections.append(table("subscriptions", "구독 (zerver_subscription)", [
                ("user", "사용자"), ("recipient", "대화방"), ("active", "활성"), ("muted", "음소거"), ("color", "색"), ("state", "행 상태"),
            ], [{"user": U(r.get("user_profile_id")), "recipient": R(r.get("recipient_id")), "active": r.get("active"),
                 "muted": r.get("is_muted"), "color": r.get("color") or "", "state": state(r), "_rc": rc(r)}
                for r in subs_t.visible()], "사용자가 참여한 채널, DM. 구독 해제하면 active=false 로 남습니다.", row_class="_rc"))
        except Exception as e:
            sections.append(error_section('subscriptions', '구독', e))

        try:
            on_disk = self._upload_index(ctx)
            att_msgs: dict = {}
            for mid, aids in att_link.items():
                for aid in aids:
                    att_msgs.setdefault(aid, []).append(mid)
            a_rows = []
            for tname, linkname, mcol in (("zerver_attachment", None, None),
                                          ("zerver_archivedattachment", "zerver_archivedattachment_messages", "archivedmessage_id")):
                t = Rows(db, tname)
                links = {}
                if linkname:
                    for r in Rows(db, linkname).live():
                        links.setdefault(r.get("archivedattachment_id"), []).append(r.get(mcol))
                for r in t.visible():
                    pid = r.get("path_id") or ""
                    f = (on_disk or {}).get(pid)
                    a_rows.append({
                        "time": T(r.get("create_time")), "name": r.get("file_name") or "", "size": r.get("size"),
                        "ctype": r.get("content_type") or "", "owner": U(r.get("owner_id")),
                        "messages": ", ".join(str(x) for x in sorted((links if linkname else att_msgs).get(r.get("id"), []))),
                        "path_id": pid, "on_disk": "있음" if f else ("없음" if on_disk is not None else ""),
                        "sha256": (f or {}).get("sha256", ""), "table": tname, "id": r.get("id"),
                        "state": state(r), "_rc": "softdel" if linkname else rc(r),
                    })
            a_rows.sort(key=lambda x: x["time"])
            counts["attachments"] = len(Rows(db, "zerver_attachment").live())
            ctx["attachments"] = {x["path_id"]: x for x in a_rows}
            sections.append(table("attachments", "첨부 파일 (zerver_attachment)", [
                ("time", "업로드 (UTC)"), ("name", "파일명"), ("size", "크기"), ("ctype", "형식"), ("owner", "올린 사람"),
                ("messages", "메시지 id"), ("on_disk", "디스크 원본"), ("path_id", "path_id (uploads/files 기준)"),
                ("sha256", "SHA-256 (디스크)"), ("table", "테이블"), ("id", "id"), ("state", "행 상태"),
            ], a_rows, "path_id 가 uploads/files 아래 실제 경로입니다. SHA-256 이 같으면 같은 파일을 여러 번 올린 것입니다. "
                       "삭제된 메시지의 첨부는 zerver_archivedattachment 에 남습니다 (연한 빨강).", row_class="_rc"))
        except Exception as e:
            sections.append(error_section('attachments', '첨부', e))

        try:
            rx = []
            for tname, archived in (("zerver_reaction", False), ("zerver_archivedreaction", True)):
                for r in Rows(db, tname).visible():
                    rx.append({"user": U(r.get("user_profile_id")), "emoji": r.get("emoji_name") or "", "code": r.get("emoji_code") or "",
                               "type": r.get("reaction_type") or "", "message": r.get("message_id"), "table": tname,
                               "state": state(r), "_rc": "softdel" if archived else rc(r)})
            sections.append(table("reactions", "반응 (zerver_reaction)", [
                ("message", "message id"), ("user", "사용자"), ("emoji", "이모지"), ("code", "코드"), ("type", "종류"),
                ("table", "테이블"), ("state", "행 상태"),
            ], rx, "반응을 취소하면 행이 삭제되어 '삭제(DB)'(빨강)로 남을 수 있습니다.", row_class="_rc"))
        except Exception as e:
            sections.append(error_section('reactions', '반응', e))

        try:
            al = []
            for r in Rows(db, "zerver_realmauditlog").visible():
                ed = r.get("extra_data")
                al.append({"time": T(r.get("event_time")), "event": f"{AUDIT_EVENTS.get(r.get('event_type'), '')} ({r.get('event_type')})",
                           "acting": U(r.get("acting_user_id")) if r.get("acting_user_id") else "",
                           "modified": U(r.get("modified_user_id")) if r.get("modified_user_id") else "",
                           "stream": R((streams.get(r.get("modified_stream_id")) or {}).get("recipient_id")) if r.get("modified_stream_id") else "",
                           "realm": f"{(realms.get(r.get('realm_id')) or {}).get('name') or ''} (id {r.get('realm_id')})",
                           "extra": display(ed) if ed not in (None, "", {}) else "", "backfilled": r.get("backfilled"),
                           "state": state(r), "_rc": rc(r)})
            al.sort(key=lambda x: x["time"])
            sections.append(table("audit", "감사 로그 (zerver_realmauditlog)", [
                ("time", "시각 (UTC)"), ("event", "이벤트"), ("acting", "행위자"), ("modified", "대상 사용자"),
                ("stream", "대상 채널"), ("realm", "조직"), ("extra", "부가 정보"), ("backfilled", "소급 생성"), ("state", "행 상태"),
            ], al, "조직, 사용자, 채널, 구독 변경 기록. 이벤트 코드는 Zulip 12.3 소스(zerver/models/realm_audit_logs.py) 기준입니다.",
                row_class="_rc"))
        except Exception as e:
            sections.append(error_section('audit', '감사 로그', e))

        try:
            d_rows = [{"time": T(r.get("last_edit_time")), "user": U(r.get("user_profile_id")), "to": R(r.get("recipient_id")),
                       "topic": r.get("topic") or "", "content": r.get("content") or "", "state": state(r), "_rc": rc(r)}
                      for r in Rows(db, "zerver_draft").visible()]
            sections.append(table("drafts", "초안 (zerver_draft)", [
                ("time", "수정 (UTC)"), ("user", "사용자"), ("to", "대상"), ("topic", "토픽"), ("content", "내용"), ("state", "행 상태"),
            ], d_rows, "초안 동기화(enable_drafts_synchronization)가 켜져 있으면 작성 중인 글이 서버에도 저장됩니다. 전송, 삭제된 초안은 '삭제(DB)'로 남을 수 있습니다.",
                row_class="_rc"))
        except Exception as e:
            sections.append(error_section('drafts', '서버 저장 초안', e))

        try:
            ua = [{"user": U(r.get("user_profile_id")), "client": clients.get(r.get("client_id"), r.get("client_id")),
                   "query": r.get("query") or "", "count": r.get("count"), "last": T(r.get("last_visit")), "state": state(r)}
                  for r in Rows(db, "zerver_useractivity").visible()]
            ua.sort(key=lambda x: x["last"])
            sections.append(table("user_activity", "사용자 활동 (zerver_useractivity)", [
                ("last", "마지막 (UTC)"), ("user", "사용자"), ("client", "클라이언트"), ("query", "요청 종류"),
                ("count", "횟수"), ("state", "행 상태"),
            ], ua, "사용자별, 클라이언트별 요청 종류와 마지막 시각. 어떤 앱(ZulipElectron = Desktop, website = 브라우저)으로 무엇을 했는지 알 수 있습니다."))
            ui = [{"user": U(r.get("user_profile_id")), "start": T(r.get("start")), "end": T(r.get("end"))}
                  for r in Rows(db, "zerver_useractivityinterval").visible()]
            ui.sort(key=lambda x: x["start"])
            sections.append(table("activity_interval", "접속 구간 (zerver_useractivityinterval)",
                                  [("start", "시작 (UTC)"), ("end", "끝 (UTC)"), ("user", "사용자")], ui,
                                  "사용자가 접속해 있던 구간 (약 15분 단위로 늘어남)."))
        except Exception as e:
            sections.append(error_section('user_activity', '활동 (UserActivity / Interval)', e))

        try:
            ses = []
            for r in Rows(db, "django_session").visible():
                uid, info = self._session_user(r.get("session_data") or "")
                ses.append({"key": r.get("session_key") or "", "expire": T(r.get("expire_date")),
                            "user": U(uid) if uid is not None else "", "data": info, "state": state(r), "_rc": rc(r)})
            sections.append(table("sessions", "세션 (django_session)", [
                ("key", "session_key"), ("user", "사용자 (_auth_user_id)"), ("expire", "만료 (UTC)"), ("data", "세션 내용"), ("state", "행 상태"),
            ], ses, "session_key 는 클라이언트 쿠키 __Host-sessionid 값과 같습니다. 만료 시각도 쿠키 만료와 일치합니다. "
                    "로그아웃하면 행이 삭제되어 '삭제(DB)'로 남을 수 있습니다.", row_class="_rc"))
        except Exception as e:
            sections.append(error_section('sessions', '세션 (django_session)', e))

        extra = {"pg": {"pgdata": pgdata.relative_to(root).as_posix(), "db_oid": target["oid"], "db_name": target["name"]}}
        return sections, extra

    @staticmethod
    def _session_user(data: str) -> tuple[int | None, str]:
        try:
            body = data.split(":")[0]
            comp = body.startswith(".")
            raw = base64.urlsafe_b64decode(body.lstrip(".") + "=" * (-len(body.lstrip(".")) % 4))
            if comp:
                dz = zlib.decompressobj()
                raw = dz.decompress(raw, 1 << 20)
                if dz.unconsumed_tail:
                    return None, "(세션 데이터가 1MB 를 넘어 해석하지 않음)"
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                return None, json.dumps(obj, ensure_ascii=False)[:2000]
            uid = obj.get("_auth_user_id")
            return (int(uid) if uid is not None and str(uid).isdigit() else None), json.dumps(obj, ensure_ascii=False)
        except Exception:
            return None, ""


    def _upload_index(self, ctx: dict) -> dict | None:
        if "upload_index" in ctx:
            return ctx["upload_index"]
        up = ctx.get("uploads")
        idx = None
        if up and (up / "files").is_dir():
            idx = {}
            files = up / "files"
            for f in files.rglob("*"):
                if not f.is_file() or f.name.endswith(".info"):
                    continue
                rel = f.relative_to(files).as_posix()
                if rel.startswith("thumbnail/"):
                    continue
                h = hashlib.sha256()
                with f.open("rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                idx[rel] = {"size": f.stat().st_size, "sha256": h.hexdigest(), "path": f}
        ctx["upload_index"] = idx
        return idx

    def uploads(self, root: Path, ctx: dict) -> list[dict]:
        cols = [("uploaded", "업로드 (tus 로그, UTC)"), ("realm", "조직 id"), ("name", "파일명"), ("size", "크기"),
                ("sha256", "SHA-256"), ("dup", "같은 내용"), ("tus_type", "형식 (tus)"), ("thumb", "썸네일"),
                ("db", "DB 첨부"), ("path_id", "path_id")]
        idx = self._upload_index(ctx)
        if idx is None:
            return [table("upload_files", "업로드 파일 (uploads/files)", cols, [], "home/zulip/uploads/files 폴더가 없습니다.")]
        files = ctx["uploads"] / "files"
        tus = self._tus_events(ctx)
        by_hash: dict[str, list[str]] = {}
        for pid, v in idx.items():
            by_hash.setdefault(v["sha256"], []).append(pid)
        att = ctx.get("attachments") or {}
        rows = []
        for pid, v in sorted(idx.items()):
            info = {}
            ip = files / (pid + ".info")
            if ip.is_file():
                try:
                    info = json.loads(ip.read_text(encoding="utf-8", errors="replace"))
                except ValueError:
                    info = {}
            thumbs = sorted(p.name for p in (files / "thumbnail" / pid).glob("*")) if (files / "thumbnail" / pid).is_dir() else []
            a = att.get(pid)
            ev = tus.get(pid, {})
            rows.append({
                "uploaded": ev.get("UploadFinished") or ev.get("UploadCreated", ""), "realm": pid.split("/")[0],
                "name": pid.split("/")[-1], "size": v["size"], "sha256": v["sha256"],
                "dup": ", ".join(p for p in by_hash[v["sha256"]] if p != pid),
                "tus_type": ((info.get("MetaData") or {}).get("filetype") or ""), "thumb": ", ".join(thumbs),
                "db": (f"id {a['id']}, {a['owner']}" if a else ("DB 미확인" if not att else "DB 에 없음")), "path_id": pid,
            })
        rows.sort(key=lambda r: r["uploaded"] or "~")
        return [table("upload_files", "업로드 파일 (uploads/files)", cols, rows,
                      "home/zulip/uploads/files/<조직id>/<2자>/<토큰>/<파일명>. 파일마다 tus 업로드 메타데이터(.info)가 있고, "
                      "이미지는 thumbnail/<path_id>/840x560.webp 썸네일이 생성됩니다. 업로드 시각은 tusd.log 에서 가져옵니다.")]

    def _tus_events(self, ctx: dict) -> dict:
        logs = ctx.get("logs")
        out: dict[str, dict] = {}
        f = logs / "tusd.log" if logs else None
        if not f or not f.is_file():
            return out
        pat = re.compile(r"^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\.\d+).*?event=(Upload\w+).*?\bid=(\S+)")
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            m = pat.match(line)
            if m:
                try:
                    dt = datetime.strptime(m[1][:23], "%Y/%m/%d %H:%M:%S.%f")
                except ValueError:
                    continue
                out.setdefault(m[3], {})[m[2]] = fmt_dt(dt)
        return out

    def avatars(self, root: Path, ctx: dict) -> dict | None:
        up = ctx.get("uploads")
        d = up / "avatars" if up else None
        if not d or not d.is_dir():
            return None
        salt = (ctx.get("secrets") or {}).get("avatar_salt", "")
        users = ctx.get("users") or {}
        lookup = {}
        if salt:
            ids = list(users) or list(range(1, 201))
            for uid in ids:
                for ver in range(1, 21):
                    lookup[hashlib.sha256(f"{uid}:{ver}:{salt}".encode()).hexdigest()[:40]] = (uid, ver)
        rows = []
        for f in sorted(p for p in d.rglob("*") if p.is_file()):
            rel = f.relative_to(d).as_posix()
            stem = f.name.split(".")[0].removesuffix("-medium")
            hit = lookup.get(stem)
            u = users.get(hit[0]) if hit else None
            rows.append({"realm": rel.split("/")[0] if "/" in rel else "", "file": rel,
                         "kind": "medium" if "-medium" in f.name else ("원본" if f.name.endswith(".original") else "기본"),
                         "size": f.stat().st_size,
                         "user": (f"{u.get('full_name')} (id {hit[0]})" if u else f"user id {hit[0]}") if hit else "",
                         "version": hit[1] if hit else ""})
        return table("avatar_files", "아바타 파일 (uploads/avatars)", [
            ("realm", "조직 id"), ("file", "경로"), ("kind", "크기"), ("size", "byte"), ("user", "사용자 (역산)"), ("version", "아바타 버전"),
        ], rows, "파일명은 sha256('<user id>:<아바타 버전>:<avatar_salt>') 앞 40자입니다. zulip-secrets.conf 의 avatar_salt 로 역산해 사용자를 찾았습니다. "
                 "클라이언트 캐시의 /user_avatars/<조직id>/<해시> 와 같은 이름입니다.")


    def _log_files(self, ctx: dict, name: str) -> list[Path]:
        d = ctx.get("logs")
        if not d:
            return []
        return sorted((p for p in d.glob(name + "*") if p.is_file() and not p.name.endswith(".gz")),
                      key=lambda p: p.name, reverse=True)

    def requests(self, root: Path, ctx: dict) -> dict:
        cols = [("time", "시각 (UTC)"), ("ip", "IP"), ("method", "메서드"), ("status", "상태"), ("path", "경로"),
                ("meaning", "해석"), ("user", "사용자"), ("realm", "조직"), ("client", "클라이언트"), ("detail", "부가"),
                ("duration", "소요"), ("file", "파일")]
        files = self._log_files(ctx, "server.log") or self._log_files(ctx, "django.log")
        users = ctx.get("users") or {}
        rows, seen = [], set()
        for f in files:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                m = REQ_RE.match(line)
                if not m or m["tag"] != "zr" or line in seen:
                    continue
                seen.add(line)
                rest = re.sub(r"^(\([^()]*\)\s*)+", "", m["rest"]).strip()
                path, _, detail = rest.partition(" ")
                meaning, cls = self._meaning(m["m"], path)
                uid = m["user"]
                u = users.get(int(uid)) if uid.isdigit() else None
                rows.append({
                    "time": m["t"][:23], "ip": m["ip"], "method": m["m"], "status": int(m["st"]), "path": path,
                    "meaning": meaning, "user": (f"{u.get('full_name')} (id {uid})" if u else (f"id {uid}" if uid.isdigit() else uid)),
                    "realm": "(기본 조직)" if m["sub"] == "root" else m["sub"], "client": m["client"],
                    "detail": detail, "duration": m["dur"], "file": f.name, "_rc": cls,
                })
        rows.sort(key=lambda r: r["time"])
        ctx["counts"]["requests"] = len(rows)
        return table("requests", "요청 로그 (server.log)", cols, rows,
                     "/var/log/zulip/server.log 의 요청 줄: 시각(UTC), 클라이언트 IP, 메서드, 상태, 경로, '<user id>@<서브도메인>', 클라이언트. "
                     "ZulipElectron/<버전> 은 Desktop 앱, Mozilla 는 브라우저입니다. 메시지 본문은 남지 않지만 전송, 삭제(빨강), 편집(주황) 시각과 IP 를 알 수 있습니다. "
                     "django.log 에도 같은 줄이 있어 server.log 를 우선합니다.", row_class="_rc")

    @staticmethod
    def _meaning(method: str, path: str) -> tuple[str, str]:
        for mth, pat, text, cls in REQUEST_MEANINGS:
            if mth and mth != method:
                continue
            m = re.match(pat, path)
            if m:
                return re.sub(r"\{(\d)\}", lambda g: m.group(int(g[1])) or "", text), {"sent": "", "login": ""}.get(cls, cls)
        return "", ""

    def auth_log(self, root: Path, ctx: dict) -> dict | None:
        files = self._log_files(ctx, "auth.log")
        if not files:
            return None
        rows = []
        pat = re.compile(r"^(\S+ \S+)\s+(\w+)\s+\[([^\]]*)\]\s+(.*)$")
        for f in files:
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                m = pat.match(line)
                if not m:
                    continue
                msg = m[4]
                ip = re.search(r"from (\S+?):", msg)
                kvs = dict(re.findall(r"(\w+)=([^;]*)", msg))
                rows.append({"time": m[1][:23].replace(",", "."), "ip": ip[1] if ip else "", "username": kvs.get("username", ""),
                             "outcome": kvs.get("outcome", ""), "subdomain": kvs.get("subdomain", ""), "backend": m[3],
                             "message": msg, "_rc": "" if kvs.get("outcome") == "success" else ("deleted" if kvs.get("outcome") else "")})
        return table("auth_log", "인증 기록 (auth.log)", [
            ("time", "시각 (UTC)"), ("ip", "IP"), ("username", "계정"), ("outcome", "결과"), ("subdomain", "서브도메인"),
            ("backend", "인증 방식"), ("message", "원문"),
        ], rows, "/var/log/zulip/auth.log - 로그인 시도 (성공, 실패). 실패는 빨강.", row_class="_rc")

    def emails(self, root: Path, ctx: dict) -> list[dict]:
        out = []
        logs = ctx.get("logs")
        rows = []
        for f in self._log_files(ctx, "send_email.log"):
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),(\d{3})\s+\w+\s+Sending (\S+) email to (.*?)(?: in (.*?))?(?: \(triggered from (\S+)\))?\s*$", line)
                if m:
                    rows.append({"time": f"{m[1]}.{m[2]}", "template": m[3], "to": m[4], "ip": m[6] or "", "line": line})
        if rows:
            out.append(table("send_email_log", "메일 발송 기록 (send_email.log)", [
                ("time", "시각 (UTC)"), ("template", "메일 종류"), ("to", "받는 사람"), ("ip", "요청 IP"), ("line", "원문"),
            ], rows, "account_registered = 가입 완료, invitation = 초대, confirm_registration = 가입 확인, notify_new_login = 새 로그인 알림."))
        d = evidence_path(root, ((ctx.get("settings") or {}).get("EMAIL_FILE_PATH") or {}).get("value"))
        if d is None and logs and (logs / "emails").is_dir():
            d = logs / "emails"
        if d:
            mails = []
            for f in sorted(d.glob("*")):
                if not f.is_file() or f.stat().st_size > 20 * 1024 * 1024:
                    continue
                raw = f.read_bytes()
                for chunk in re.split(rb"\n-{60,}\n", raw):
                    if not chunk.strip():
                        continue
                    try:
                        mails.append(self._mail_row(chunk.strip(), f.name))
                    except Exception as e:
                        mails.append({"time": "", "from": "", "to": "", "subject": f"(해석 실패: {type(e).__name__})",
                                      "body": "", "links": "", "file": f.name})
            mails.sort(key=lambda r: r["time"])
            out.append(table("emails", "발송 메일 원문 (emails/)", [
                ("time", "Date (UTC)"), ("from", "보낸 사람"), ("to", "받는 사람"), ("subject", "제목"),
                ("links", "본문 링크"), ("body", "본문 (text)"), ("file", "파일"),
            ], mails, "settings.py 의 EMAIL_BACKEND 가 filebased 라 서버가 보낸 메일이 파일로 저장되었습니다. "
                      "가입, 초대 확인 링크, 새 로그인 알림(접속 기기, 시각)이 들어 있습니다. HTML 본문은 표시하지 않습니다."))
        return out

    @staticmethod
    def _mail_row(chunk: bytes, fname: str) -> dict:
        msg = email.message_from_bytes(chunk, policy=email.policy.default)
        try:
            dt = parsedate_to_datetime(msg["Date"]) if msg["Date"] else None
        except (TypeError, ValueError):
            dt = None
        body = ""
        try:
            part = msg.get_body(preferencelist=("plain",))
            body = part.get_content() if part else ""
        except Exception:
            body = ""
        return {"time": _to_utc_text(dt), "from": str(msg["From"] or ""), "to": str(msg["To"] or ""),
                "subject": str(msg["Subject"] or ""), "body": body.strip(),
                "links": ", ".join(sorted(set(re.findall(r"https?://[^\s)>\]]+", body)))), "file": fname}

    def other_logs(self, root: Path, ctx: dict) -> dict | None:
        d = ctx.get("logs")
        if not d:
            return None
        skip = {"install.log"}
        rows = []
        for f in sorted(p for p in d.rglob("*.log") if p.is_file() and p.parent == d and p.name not in skip):
            text = f.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                if not line.strip():
                    continue
                t, lv, msg = self._split_log_line(line)
                if t or not rows or rows[-1]["file"] != f.name:
                    rows.append({"time": t, "file": f.name, "level": lv, "message": msg})
                else:
                    rows[-1]["message"] += "\n" + line
        rows.sort(key=lambda r: (r["time"] or "~", r["file"]))
        return table("server_logs", "서버 로그 (/var/log/zulip)", [
            ("time", "시각 (UTC)"), ("file", "파일"), ("level", "수준"), ("message", "내용"),
        ], rows, "/var/log/zulip/*.log 전체 (install.log 제외). 접두 시각은 UTC 이고, +09:00 처럼 시간대가 붙은 줄은 UTC 로 바꿨습니다. "
                 "시각 없는 줄(트레이스백 등)은 앞 줄에 붙였습니다. message_retention.log 의 'Archived N messages' 는 메시지 삭제 기록입니다.")

    @staticmethod
    def _split_log_line(line: str) -> tuple[str, str, str]:
        for pat, fmt in LOG_TS:
            m = pat.match(line)
            if m:
                try:
                    t = datetime.strptime(m[1], fmt).strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    return "", "", line
                lv = LEVEL_RE.match(m[3])
                return f"{t}.{m[2]}", lv[1] if lv else "", lv[2] if lv else m[3]
        m = re.search(r'"?time"?\s*[:=]\s*"(\d{4}-\d\d-\d\dT[\d:.]+(?:Z|[+-]\d\d:?\d\d))"', line)
        if m:
            try:
                s = m[1].replace("Z", "+00:00")
                s = re.sub(r"(\.\d{6})\d+", r"\1", s)
                lv = re.search(r'"?level"?\s*[:=]\s*"?(\w+)', line)
                return fmt_dt(datetime.fromisoformat(s).astimezone(timezone.utc)), lv[1] if lv else "", line
            except ValueError:
                pass
        return "", "", line

    def install_log(self, root: Path, ctx: dict) -> dict | None:
        d = ctx.get("logs")
        f = d / "install.log" if d else None
        if not f or not f.is_file():
            return None
        rows, seen, versions = [], set(), set()
        for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").split("\n"), 1):
            clean = re.sub(r"\x1b\[[0-9;]*m", "", line)
            text = clean.strip()
            if text in seen:
                continue
            m = re.search(r"zulip-server-(\d[\w.]*)", text)
            if m and m[1] in versions:
                continue
            host = ((ctx.get("settings") or {}).get("EXTERNAL_HOST") or {}).get("value") or "\x00"
            if m or re.search(r"/home/zulip/deployments/\d{4}-|single-use link", text) or (
                    isinstance(host, str) and re.search(r"https?://" + re.escape(host), text)):
                if m:
                    versions.add(m[1])
                seen.add(text)
                rows.append({"line": i, "text": text})
        if not rows:
            return None
        return table("install_log", "설치 기록 (install.log 요약)", [("line", "줄"), ("text", "내용")], rows,
                     "/var/log/zulip/install.log 에서 설치 패키지 버전, 배포 경로, URL 이 있는 줄만 뽑았습니다. "
                     "마지막의 /new/<키> 링크는 첫 조직을 만드는 일회용 링크이며, 요청 로그의 /new/ 접속 시각과 대조할 수 있습니다. "
                     "전체 원문은 '파일 목록'의 원본 파일을 보세요.")


    FINDINGS_DESC = (
        "분석 결과 표들에서 삭제, 편집, 변조 정황만 모았습니다. 확실 = 기록으로 확인되는 사실, 추정 = 정황(다른 원인도 가능). "
        "점검 항목: 메시지 삭제, 보존 정책 보관(zerver_archivedmessage), 편집, 토픽 이동(edit_history), DB 에서 지워진 행, "
        "편집 표시 없이 바뀐 내용(이전 버전 대조), message id 결번(순차 번호), 시각 역전, 첨부 DB↔uploads 불일치, "
        "사용자 비활성화, 채널 보관, 감사 로그 등 삭제, 요청 로그(server.log)의 삭제, 편집 요청과 DB 기록 대조. "
        "행을 누르고 [근거 행으로 이동]으로 원래 표를 엽니다."
    )

    def findings(self, sections: list[dict]) -> list[dict]:
        S = {s["id"]: s for s in sections}
        has = lambda sid: sid in S and S[sid].get("type") == "table"
        rows_of = lambda sid: S[sid]["rows"] if has(sid) else []
        nm = lambda s: split_label(s)[0].split(" <")[0]
        out: list[dict] = []
        self.findings_notes = [f"{t} 섹션을 해석하지 못해 점검하지 않았습니다" for sid, t in
                               (("messages", "메시지"), ("edit_history", "편집 이력"), ("attachments", "첨부 파일"))
                               if not has(sid)]
        basis = "메시지"

        msgs = rows_of("messages")

        def tgt(r):
            return f"message {r.get('id')}, {nm(r.get('sender'))}, {r.get('conv')}"

        def ref(r):
            return {"section": "messages", "match": {"id": r.get("id"), "table": r.get("table"), "rid": r.get("rid")}}

        live = {str(r.get("id")): r for r in msgs if r.get("state") == "live" and r.get("table") == "zerver_message"}
        archived = {str(r.get("id")): r for r in msgs if r.get("state") == "live" and r.get("table") == "zerver_archivedmessage"}
        for r in msgs:
            content = short(r.get("content"))
            if r.get("table") == "zerver_archivedmessage" and r.get("state") == "live":
                tags = r.get("tags") or ""
                m = re.search(r"\((\d{4}-\d\d-\d\d [\d:.]+)\)", tags)
                auto = "보존 정책" in tags
                out.append(finding(CERTAIN, "메시지 자동 보관 (보존 정책)" if auto else "메시지 삭제", m[1] if m else "", tgt(r),
                                   ("보존 정책에 따라 보관 테이블로 옮겨졌습니다." if auto else "삭제되어 보관 테이블(zerver_archivedmessage)로 옮겨졌습니다.")
                                   + (" 이후 복원됐습니다." if "복원됨" in tags else "") + f" 남은 내용: \"{content}\"",
                                   basis, ref(r), "softdel"))
            elif r.get("_rc") == "deleted":
                carved = r.get("source") == SOURCE_KO.get("carved")
                if r.get("table") == "zerver_archivedmessage":
                    out.append(finding(INFERRED if carved else CERTAIN, "보관 메시지 완전 삭제", r.get("time"), tgt(r),
                                       f"삭제 보관 테이블의 행까지 DB 에서 지워졌습니다 (출처: {r.get('source')}). 보관 데이터 정리(기본 30일 후)라는 "
                                       f"정상 동작으로도 생기며, 그 전이라면 조직 삭제, DB 직접 삭제 정황입니다. 남은 내용: \"{content}\"",
                                       basis, ref(r), "deleted"))
                elif str(r.get("id")) not in archived:
                    out.append(finding(INFERRED, "보관 기록 없는 메시지 행 삭제", r.get("time"), tgt(r),
                                       f"zerver_message 행이 DB 에서 지워졌는데 같은 id 의 보관 행이 없습니다 (출처: {r.get('source')}). "
                                       "보관 데이터 정리(기본 30일 후), 조직 삭제, DB 직접 삭제 정황입니다. "
                                       f"남은 내용: \"{content}\"", basis, ref(r), "deleted"))
            if r.get("state") == "live":
                t, e = parse_utc(r.get("time")), parse_utc(r.get("edit"))
                if t and e and e < t:
                    out.append(finding(INFERRED, "시각 역전", r.get("time"), tgt(r),
                                       f"마지막 편집 시각({r.get('edit')})이 보낸 시각보다 앞섭니다 - DB 직접 수정 또는 서버 시계 조정 정황.",
                                       basis, ref(r)))

        for r in msgs:
            if r.get("_rc") != "updated" or r.get("table") != "zerver_message":
                continue
            cur = live.get(str(r.get("id")))
            if cur and (r.get("content") or "") != (cur.get("content") or "") and not cur.get("edit"):
                out.append(finding(INFERRED, "편집 표시 없는 내용 변경", cur.get("time"), tgt(cur),
                                   f"이전 버전(출처: {r.get('source')})의 내용 \"{short(r.get('content'))}\" 이 현재 \"{short(cur.get('content'))}\" 와 다르지만 "
                                   "편집 시각(last_edit_time), 편집 이력이 없습니다 - 앱 편집이 아닌 DB 직접 수정 가능성.", basis, ref(r), "updated"))

        ids = sorted({int(r["id"]) for r in msgs if str(r.get("id", "")).isdigit() and r.get("source") != SOURCE_KO.get("carved")})
        deleted_req: dict[int, dict] = {}
        for q in rows_of("requests"):
            m = re.match(r"메시지 삭제 \(id (\d+)\)", q.get("meaning") or "")
            if m:
                deleted_req.setdefault(int(m[1]), q)
        gaps = [(a + 1, b - 1) for a, b in zip(ids, ids[1:]) if b - a > 1]
        why = ("현재, 보관 테이블 어디에도 없어 행이 DB 에서 완전히 지워졌거나(보관 데이터 정리, 직접 삭제), 다른 조직의 메시지이거나, "
               "롤백된 전송일 수 있습니다. 맨 앞, 맨 뒤 번호는 알 수 없어 보지 않습니다.")
        if 0 < len(gaps) <= 20:
            for a, b in gaps:
                reqs = [q for i, q in deleted_req.items() if a <= i <= b]
                out.append(finding(INFERRED, "message id 결번", "", f"message id {a}" + (f" ~ {b}" if b > a else ""),
                                   f"메시지 id 가 {a}" + (f"~{b} ({b - a + 1}개)" if b > a else "") + f" 비어 있습니다. {why}"
                                   + (f" 요청 로그에 이 범위의 삭제 요청 {len(reqs)}건이 있습니다 ({reqs[0].get('time')} {reqs[0].get('user')})." if reqs else ""),
                                   basis, {"section": "messages", "match": {"id": str(a - 1)}}))
        elif gaps:
            total = sum(b - a + 1 for a, b in gaps)
            out.append(finding(INFERRED, "message id 결번", "", f"message id {ids[0]} ~ {ids[-1]} 사이",
                               f"빈 구간 {len(gaps)}곳, 빈 번호 {total}개. 큰 구간: "
                               + ", ".join(f"{a}~{b}" for a, b in sorted(gaps, key=lambda g: g[0] - g[1])[:10]) + f". {why}",
                               basis, {"section": "messages", "match": {"id": str(gaps[0][0] - 1)}}))

        edited_ids = ({str(r.get("id")) for r in rows_of("edit_history")} | {k for k, v in live.items() if v.get("edit")}
                      | {k for k, v in archived.items() if v.get("edit")})
        for q in rows_of("requests"):
            mean, status = q.get("meaning") or "", str(q.get("status") or "")
            m = re.match(r"메시지 (삭제|편집, 이동) \(id (\d+)\)", mean)
            if not m or not status.startswith("2") or not has("messages"):
                continue
            mid = m[2]
            qref = {"section": "requests", "match": {"time": q.get("time"), "path": q.get("path")}}
            if m[1] == "삭제" and mid in live and mid not in archived:
                out.append(finding(INFERRED, "삭제 요청 후에도 메시지 남음", q.get("time"), f"message {mid}, 요청 {q.get('user')}",
                                   f"server.log 에 성공한 삭제 요청({q.get('time')}, {q.get('client')})이 있지만 메시지가 현재 테이블에 그대로 있습니다 - "
                                   "삭제 후 DB 에 직접 되살렸거나 다른 조직의 같은 id 일 수 있습니다.", "요청 로그 ↔ 메시지", qref))
            elif m[1] == "편집, 이동" and mid not in edited_ids and has("edit_history"):
                out.append(finding(INFERRED, "편집 요청 기록과 편집 이력 불일치", q.get("time"), f"message {mid}, 요청 {q.get('user')}",
                                   f"server.log 에 성공한 편집, 이동 요청({q.get('time')})이 있지만 이 메시지의 편집 이력, 편집 시각이 없습니다 - "
                                   "편집 이력이 지워졌거나(DB 직접 수정) 메시지 행이 바뀌었을 수 있습니다.", "요청 로그 ↔ 편집 이력", qref, "updated"))

        for r in rows_of("edit_history"):
            t = f"message {r.get('id')}, {nm(r.get('user'))}"
            eref = {"section": "edit_history", "match": {"id": r.get("id"), "time": r.get("time")}}
            if r.get("prev_content"):
                out.append(finding(CERTAIN, "메시지 편집", r.get("time"), t,
                                   f"편집 전: \"{short(r.get('prev_content'))}\" → 현재: \"{short(r.get('current'))}\" (edit_history)", "편집 이력", eref, "updated"))
            if r.get("prev_topic") or r.get("prev_stream"):
                mv = []
                if r.get("prev_topic"):
                    mv.append(f"토픽 \"{r.get('prev_topic')}\" → \"{r.get('topic')}\"")
                if r.get("prev_stream"):
                    mv.append(f"채널 id {r.get('prev_stream')} → {r.get('stream')}")
                out.append(finding(CERTAIN, "메시지 이동 (토픽, 채널)", r.get("time"), t, ", ".join(mv) + " (edit_history)", "편집 이력", eref))

        for sid, title, label, keys in (
            ("users", "사용자 (zerver_userprofile)", lambda r: f"사용자 {r.get('name')} (id {r.get('id')})", ("id",)),
            ("streams", "채널 (zerver_stream)", lambda r: f"채널 #{r.get('name')} (id {r.get('id')})", ("id",)),
            ("attachments", "첨부 파일 (zerver_attachment)", lambda r: f"첨부 {r.get('name')} (id {r.get('id')}), {nm(r.get('owner'))}", ("id", "table")),
            ("reactions", "반응 (zerver_reaction)", lambda r: f"반응 :{r.get('emoji')}:, {nm(r.get('user'))}, message {r.get('message')}", ("message", "user", "emoji")),
            ("subscriptions", "구독 (zerver_subscription)", lambda r: f"구독 {nm(r.get('user'))}, {r.get('recipient')}", ("user", "recipient")),
            ("audit", "감사 로그 (zerver_realmauditlog)", lambda r: f"감사 로그 {r.get('event')}, {nm(r.get('acting'))}", ("time", "event")),
            ("drafts", "초안 (zerver_draft)", lambda r: f"초안, {nm(r.get('user'))}, {r.get('to')}", ("time", "user")),
        ):
            for r in rows_of(sid):
                m = {k: r.get(k) for k in (*keys, "state")}
                if r.get("_rc") == "deleted":
                    extra = {"audit": " 감사 로그는 앱이 지우지 않으므로 의도적 삭제 정황입니다.",
                             "drafts": " 초안은 전송, 삭제 때 앱이 지우므로 정상 동작일 수 있습니다."}.get(sid, "")
                    out.append(finding(INFERRED if sid == "drafts" else CERTAIN, "DB 행 삭제", r.get("time") or r.get("created") or r.get("joined"),
                                       label(r), f"{title} 행이 DB 에서 지워졌습니다.{extra}"
                                       + (f" 내용: \"{short(r.get('content'))}\"" if sid == "drafts" else ""), title, {"section": sid, "match": m}, "deleted"))
                elif sid == "users" and r.get("_rc") == "softdel":
                    out.append(finding(CERTAIN, "사용자 비활성화", "", label(r), "is_active 가 꺼져 있습니다 (행은 남아 있음). 관리자의 정상 기능으로도 생깁니다.",
                                       title, {"section": sid, "match": m}, "softdel"))
                elif sid == "streams" and r.get("deactivated") not in ("", None, "False", "false"):
                    out.append(finding(CERTAIN, "채널 보관", "", label(r), "채널이 비활성화(보관)되어 있습니다. 관리자의 정상 기능으로도 생깁니다.",
                                       title, {"section": sid, "match": m}, "softdel"))
        if rows_of("upload_files"):
            for r in rows_of("attachments"):
                if r.get("on_disk") == "없음" and r.get("state") == "live":
                    out.append(finding(INFERRED, "첨부 원본 없음", r.get("time"), f"첨부 {r.get('name')} (id {r.get('id')})",
                                       f"zerver_attachment 에 기록된 파일(uploads/files/{r.get('path_id')})이 업로드한 증거에 없습니다 - 디스크에서 지워졌거나 수집 범위에서 빠졌습니다.",
                                       "첨부 파일 (zerver_attachment)", {"section": "attachments", "match": {"id": r.get("id"), "table": r.get("table")}}, "deleted"))
        if has("attachments"):
            for r in rows_of("upload_files"):
                if not r.get("db"):
                    out.append(finding(INFERRED, "DB 기록 없는 업로드 파일", r.get("uploaded"), f"파일 {r.get('name')}, {r.get('path_id')}",
                                       "uploads/files 에는 파일이 있지만 zerver_attachment 행이 없습니다 - 첨부 행 삭제 또는 업로드만 하고 전송하지 않은 파일일 수 있습니다.",
                                       "업로드 파일 (uploads/files)", {"section": "upload_files", "match": {"path_id": r.get("path_id")}}))
        return out

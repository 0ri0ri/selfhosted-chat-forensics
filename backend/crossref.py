from __future__ import annotations

import re
from urllib.parse import urlparse

from .parsers.base import (CERTAIN, INFERRED, finding, findings_summary, findings_table, parse_utc, short,
                           split_label, table)
from .parsers.client.mattermost import EMPTY_DRAFT

DEFAULT_PORTS = {"http": 80, "https": 443}


def _section(result: dict, sid: str, kind: str = "table") -> dict | None:
    for s in result.get("sections", []):
        if s.get("id") == sid and s.get("type") == kind:
            return s
    return None


def _rows(result: dict, sid: str) -> list[dict]:
    s = _section(result, sid)
    return s["rows"] if s else []


def _kv(result: dict, sid: str) -> dict:
    s = _section(result, sid, "kv")
    return {r["key"]: r["value"] for r in s["rows"]} if s else {}


def _host(url) -> str:
    s = str(url or "").strip()
    if not s:
        return ""
    try:
        u = urlparse(s if "://" in s else "http://" + s)
        port = u.port
        if port and DEFAULT_PORTS.get(u.scheme.lower()) == port:
            port = None
        return f"{(u.hostname or '').lower()}{':' + str(port) if port else ''}"
    except (ValueError, TypeError, AttributeError):
        return s.lower()


def _gap(a, b) -> float | None:
    x, y = parse_utc(a), parse_utc(b)
    return abs((x - y).total_seconds()) if x and y else None


def _before(a, b) -> bool | None:
    x, y = parse_utc(a), parse_utc(b)
    return (x < y) if x and y else None


CROSS_COLS = [("certainty", "확실성"), ("category", "분류"), ("time", "시각 (UTC)"), ("target", "대상"),
              ("detail", "내용"), ("basis", "근거")]

USER_KEY_RE = re.compile(r"user_(?:prev_team|team_\w+?):([a-z0-9]{26})")


def mattermost(client: dict, server: dict) -> dict:
    name = lambda s: split_label(s)[0]
    id_of = lambda s: split_label(s)[1]
    out: list[dict] = []
    notes: list[str] = []

    has_posts = _section(server, "posts") is not None
    has_cache = _section(client, "cache_posts") is not None
    has_users = _section(server, "users") is not None
    if not has_posts:
        notes.append("서버 posts 를 해석하지 못해 메시지, 초안 대조를 하지 않았습니다")
    if not has_cache:
        notes.append("클라이언트 캐시 메시지가 없어 메시지 대조를 하지 않았습니다")

    s_posts = _rows(server, "posts")
    by_id: dict[str, list[dict]] = {}
    for r in s_posts:
        by_id.setdefault(r.get("id"), []).append(r)
        if r.get("original"):
            by_id.setdefault(r["original"], []).append(r)
    live = {r["id"]: r for r in s_posts if r.get("state") == "live"}
    msg = lambda r: (r or {}).get("message") or ""

    s_times = [t for r in s_posts for t in (parse_utc(r.get(k)) for k in ("create", "edit", "delete", "update")) if t]
    s_latest = max(s_times) if s_times else None

    acc_rows = []
    site = next((v for k, v in _kv(server, "config").items() if "SiteURL" in k), "")
    c_servers = _rows(client, "servers")
    s_host = _host(site)
    same_server = None
    if s_host and c_servers:
        same_server = any(_host(s.get("url")) == s_host for s in c_servers)
    srv_ref = {"mode": "client", "section": "servers", "match": {"url": c_servers[0].get("url")}} if c_servers else None
    acc_rows.append({"item": "접속 서버", "client": ", ".join(f"{s.get('name')} {s.get('url')}" for s in c_servers),
                     "server": site, "judge": {True: "일치", False: "불일치"}.get(same_server, "판단 불가 (정보 없음)"),
                     "certainty": CERTAIN if same_server is not None else "", "_ref": srv_ref})
    if same_server is False:
        out.append(finding(INFERRED, "다른 서버 의심", "", "접속 서버",
                           f"클라이언트에 등록된 서버({', '.join(str(s.get('url') or '') for s in c_servers)})의 주소가 서버 설정 SiteURL({site})과 다릅니다. "
                           "IP, 도메인, 내부/외부 주소만 다른 같은 서버일 수 있습니다. 같은 서버가 아니면 아래 대조는 의미가 없어, "
                           "이 경우 '없다'는 판단은 모두 추정으로 낮췄습니다.", "접속 서버 ↔ 서버 설정", srv_ref))

    def certain_absence(when) -> tuple[str, str]:
        if same_server is not True:
            return INFERRED, (" 접속 서버 주소가 SiteURL 과 달라 추정으로 둡니다." if same_server is False
                              else " 같은 서버인지 확인하지 못해(접속 서버 정보 없음) 추정으로 둡니다.")
        t = parse_utc(when)
        if s_latest is None or t is None:
            return INFERRED, " 서버, 캐시 시각을 비교할 수 없어 추정으로 둡니다."
        if t > s_latest:
            return INFERRED, f" 캐시 시각이 서버 기록의 마지막 시각({s_latest:%Y-%m-%d %H:%M:%S})보다 늦어, 서버 DB 가 더 이른 시점의 것일 수 있습니다."
        return CERTAIN, ""

    def s_ref(r):
        return {"mode": "server", "section": "posts", "match": {"id": r.get("id"), "rid": r.get("rid", "")}}

    def server_state(r):
        if r is None:
            return ""
        if r.get("_rc") == "deleted":
            return "DB 에서 삭제된 행"
        if r.get("delete") and "편집 전 원본" not in (r.get("tags") or ""):
            return "삭제됨 (" + (r.get("tags") or "deleteat") + ")"
        if r.get("edit"):
            return "편집됨"
        return "live"

    uids: dict[str, str] = {}
    for r in _rows(client, "localstorage"):
        m = USER_KEY_RE.match(r.get("key") or "")
        if m and m[1] not in uids:
            uids[m[1]] = r.get("key")

    m_rows = []
    counts = {"same": 0, "older": 0, "gone": 0, "deleted": 0, "missing": 0, "diff": 0}
    basis = "캐시 메시지 ↔ 메시지 (posts)"
    for c in (_rows(client, "cache_posts") if has_posts else []):
        pid, ctext = c.get("post_id"), msg(c)
        tgt = f"post {pid}, {name(c.get('user'))}, {name(c.get('channel'))}"
        c_ref = {"mode": "client", "section": "cache_posts", "match": {"post_id": pid}}
        vers = by_id.get(pid, [])
        cur = live.get(pid)
        same_ver = next((v for v in vers if msg(v) == ctext), None)
        row = {"result": "", "id": pid, "create": c.get("create"), "channel": c.get("channel"), "user": c.get("user"),
               "client": ctext, "server": msg(cur), "server_state": server_state(cur),
               "cached": c.get("cached"), "_rc": "", "_ref": c_ref}
        if not vers:
            cert, why = certain_absence(c.get("cached"))
            row.update(result="서버에 없음", _rc="deleted")
            counts["missing"] += 1
            out.append(finding(cert, "서버에 없는 메시지", c.get("create"), tgt,
                               f"클라이언트 캐시(캐시 시각 {c.get('cached')})에는 있지만 서버 posts 에는 이 id 가 삭제, 이전 버전을 포함해 전혀 없습니다. "
                               f"서버에서 영구 삭제됐을 수 있습니다.{why} 내용: \"{short(ctext)}\"", basis, c_ref, "deleted"))
        elif cur is None:
            ref_row = same_ver or vers[0]
            row.update(result="서버에서 지워진 글", _rc="deleted", server=msg(ref_row), server_state=server_state(ref_row))
            counts["gone"] += 1
            out.append(finding(CERTAIN, "서버에서 지워진 글의 원문 (클라이언트 보유)", ref_row.get("create") or c.get("create"), tgt,
                               f"서버 posts 에는 이 글의 현재 행이 없고 {server_state(ref_row) or '이전 버전'}만 남아 있습니다. "
                               f"클라이언트 캐시 내용 \"{short(ctext)}\"" + (" 은 남은 서버 기록과 같습니다." if same_ver else
                                                                       f" 은 남은 서버 기록 \"{short(msg(ref_row))}\" 과 다릅니다."),
                               basis, s_ref(ref_row), "deleted"))
        elif msg(cur) == ctext:
            row["result"] = "일치"
            counts["same"] += 1
        elif same_ver is not None:
            row.update(result="편집 전 원문 보유", _rc="updated")
            counts["older"] += 1
            if cur.get("edit"):
                out.append(finding(CERTAIN, "편집 전 원문 (클라이언트 보유)", c.get("cached"), tgt,
                                   f"클라이언트 캐시의 내용 \"{short(ctext)}\" 은 서버의 이전 기록({same_ver.get('tags') or same_ver.get('state')}, "
                                   f"출처 {same_ver.get('source')})과 같고, 서버 현재 내용은 \"{short(msg(cur))}\" 입니다 (편집 시각 {cur.get('edit')}). "
                                   "서버 편집 기록과 클라이언트가 서로 뒷받침합니다.", basis, s_ref(same_ver), "updated"))
            else:
                out.append(finding(INFERRED, "편집 표시 없는 변경 (클라이언트 원문 보유)", c.get("cached"), tgt,
                                   f"클라이언트 캐시와 서버 이전 기록은 \"{short(ctext)}\" 인데 서버 현재 내용은 \"{short(msg(cur))}\" 이고 "
                                   "편집 시각(editat)이 비어 있습니다 - 앱 화면 편집이 아닌 DB 직접 수정 가능성.", basis, s_ref(same_ver), "updated"))
        else:
            row.update(result="내용 불일치", _rc="deleted")
            counts["diff"] += 1
            out.append(finding(INFERRED, "서버 기록과 다른 내용", c.get("cached"), tgt,
                               f"같은 id 인데 클라이언트 캐시 \"{short(ctext)}\" 이 서버의 현재, 이전 기록 어느 것과도 같지 않습니다. "
                               f"서버 현재 \"{short(msg(cur))}\". 서버 DB 를 앱을 거치지 않고 고쳤거나, 편집 기록이 지워졌을 수 있습니다.",
                               basis, s_ref(cur), "deleted"))
        if cur and cur.get("delete"):
            row.update(result=row["result"] + ", 서버에서 삭제됨", _rc="softdel")
            counts["deleted"] += 1
            first = _before(c.get("cached"), cur.get("delete"))
            if first:
                out.append(finding(CERTAIN, "삭제 전 수신 확인", cur.get("delete"), tgt,
                                   f"서버에서 {cur.get('delete')} 에 삭제된 메시지({server_state(cur)})를 이 PC 가 그 전({c.get('cached')})에 받아 캐시했습니다. "
                                   f"클라이언트 내용: \"{short(ctext)}\"", basis, s_ref(cur), "softdel"))
            else:
                out.append(finding(INFERRED, "삭제된 메시지 보유 (시각 확인 필요)", cur.get("delete"), tgt,
                                   f"서버에서 삭제된 메시지({server_state(cur)})를 이 PC 가 캐시에 갖고 있습니다. 캐시 시각({c.get('cached') or '없음'})이 "
                                   f"삭제 시각({cur.get('delete')}) 이후이거나 비교할 수 없어, PC, 서버 시계 차이를 확인해야 합니다.",
                                   basis, s_ref(cur), "softdel"))
        g = _gap(c.get("create"), cur.get("create")) if cur else None
        if g is not None and g > 1:
            out.append(finding(INFERRED, "작성 시각 불일치", cur.get("create"), tgt,
                               f"같은 id 의 작성 시각이 클라이언트 {c.get('create')} / 서버 {cur.get('create')} 로 {g:.0f}초 다릅니다 - 서버 DB 시각 수정 정황.",
                               basis, s_ref(cur)))
        m_rows.append(row)

    by_chan_text: dict[tuple, list[dict]] = {}
    for r in s_posts:
        if uids and id_of(r.get("user")) not in uids:
            continue
        by_chan_text.setdefault((id_of(r.get("channel")), msg(r).strip()), []).append(r)
    drafts = [d for d in (_rows(client, "drafts") if has_posts else []) if d.get("message") and d["message"] != EMPTY_DRAFT]
    seen, d_rows = set(), []
    texts_by_key: dict[str, list[str]] = {}
    for d in drafts:
        texts_by_key.setdefault(d.get("key"), []).append(d["message"].strip())
    sent = 0
    for d in sorted(drafts, key=lambda d: d.get("update") or d.get("saved") or ""):
        text = d["message"].strip()
        k = (d.get("key"), text)
        if k in seen:
            continue
        seen.add(k)
        when = d.get("update") or d.get("saved") or ""
        same = by_chan_text.get((id_of(d.get("channel")), text), [])
        if parse_utc(when):
            near = [(g, p) for p in same if (g := _gap(p.get("create"), when)) is not None and g <= 86400]
            p = min(near, key=lambda x: x[0])[1] if near else None
        else:
            p = same[0] if len(same) == 1 else None
        row = {"result": "", "channel": d.get("channel"), "kind": d.get("kind"), "message": d["message"], "update": when,
               "post": "", "post_create": "", "post_user": "", "post_state": "", "_rc": "",
               "_ref": {"mode": "client", "section": "drafts", "match": {"key": d.get("key"), "message": d["message"]}}}
        if p is not None:
            pid = p.get("original") or p.get("id")
            cur = live.get(pid)
            sent += 1
            row.update(post=pid, post_create=p.get("create"), post_user=p.get("user"), post_state=server_state(cur or p))
            if cur is None:
                row.update(result="전송 후 DB 에서 삭제", _rc="deleted")
            elif cur.get("delete"):
                row.update(result="전송 후 삭제", _rc="softdel")
            elif msg(cur).strip() != text:
                row.update(result="전송 후 편집", _rc="updated")
            else:
                row["result"] = "전송됨" if parse_utc(when) else "전송됨 (초안 시각 없음)"
        else:
            longer = [t for t in texts_by_key.get(d.get("key"), []) if t != text and t.startswith(text)]
            if text.startswith("/") or longer or len(text) < 2:
                continue
            row.update(result="서버에 전송 기록 없음" if parse_utc(when) or not same else "판단 불가 (초안 시각 없음)", _rc="unknown")
        d_rows.append(row)
    unsent = sum(1 for r in d_rows if r["result"] == "서버에 전송 기록 없음")

    s_users = {r.get("id"): r for r in _rows(server, "users")}
    if not uids:
        acc_rows.append({"item": "로그인 계정", "client": "(Local Storage 에 계정 id 키 없음)", "server": "",
                         "judge": "판단 불가", "certainty": "", "_ref": None})
    for uid, lskey in uids.items():
        u = s_users.get(uid)
        acc_rows.append({"item": "로그인 계정 (Local Storage 키의 user id)", "client": uid,
                         "server": f"{u.get('username')}, {u.get('email')}, 마지막 로그인 {u.get('lastlogin') or '-'}" if u
                         else ("(서버 users 에 없음)" if has_users else "(서버 users 해석 안 됨)"),
                         "judge": "일치" if u else ("서버에 없음" if has_users else "판단 불가"),
                         "certainty": CERTAIN if (u or has_users) else "",
                         "_ref": {"mode": "server", "section": "users", "match": {"id": uid}} if u else None})
        if not u and has_users:
            cert, why = (CERTAIN, "") if same_server is True else (INFERRED, " 같은 서버로 확인되지 않아 추정으로 둡니다.")
            out.append(finding(cert, "서버에 없는 계정", "", f"user {uid}",
                               "이 PC 의 앱 저장소에 남은 계정 id 가 서버 users 에 없습니다 (삭제된 행 포함) - 계정 행 삭제 또는 다른 서버." + why,
                               "Local Storage ↔ 사용자 (users)", {"mode": "client", "section": "localstorage", "match": {"key": lskey}}))

    sessions = _rows(server, "sessions")
    for ck in _rows(client, "cookies"):
        if ck.get("name") != "MMAUTHTOKEN":
            continue
        s, g = None, None
        if parse_utc(ck.get("expires")):
            near = [(gg, x) for x in sessions if (gg := _gap(x.get("expires"), ck.get("expires"))) is not None and gg <= 5]
            if near:
                g, s = min(near, key=lambda x: x[0])
        acc_rows.append({
            "item": "인증 쿠키 MMAUTHTOKEN ↔ 서버 세션",
            "client": f"{ck.get('host')}, 생성 {ck.get('created')}, 만료 {ck.get('expires') or '(세션 쿠키)'}, 마지막 접근 {ck.get('last_access')}",
            "server": (f"{s.get('user')}, {s.get('platform')} {s.get('os')} {s.get('browser')}, 생성 {s.get('create')}, "
                       f"만료 {s.get('expires')}, 마지막 활동 {s.get('last')}, {s.get('state')}") if s
            else "(만료 시각이 맞는 세션 없음 - 로그아웃, 만료로 지워졌거나 세션 연장으로 만료가 바뀜)",
            "judge": f"같은 세션 (만료 시각 차 {g:.3f}초)" if s else "대응 세션 없음",
            "certainty": INFERRED if s else "",
            "_ref": {"mode": "server", "section": "sessions", "match": {"id": s.get("id")}} if s else None,
        })

    tl = []

    def ev(time, side, kind, user, text, ref):
        if time:
            tl.append({"time": time, "side": side, "kind": kind, "user": user, "text": short(text, 200), "_ref": ref})

    login_user = ", ".join(str(s_users[u].get("username")) for u in uids if u in s_users)
    for r in _rows(client, "localstorage"):
        if r.get("meaning") and not (r.get("key") or "").startswith("_localforage"):
            ev(r.get("time"), "Client", "앱 저장소 " + ("삭제" if r.get("state") == "deleted" else "기록"), login_user,
               f"{r.get('meaning')}: {r.get('key')} = {r.get('value')}", {"mode": "client", "section": "localstorage", "match": {"seq": r.get("seq")}})
    for r in d_rows:
        ev(r["update"], "Client", "초안 입력", login_user, f"[{name(r['channel'])}] {r['message']} → {r['result']}", r["_ref"])
    for r in _rows(client, "cookies"):
        if r.get("name") == "MMAUTHTOKEN":
            ev(r.get("created"), "Client", "로그인 쿠키 생성", login_user, r.get("host"),
               {"mode": "client", "section": "cookies", "match": {"name": r.get("name"), "host": r.get("host")}})
    for r in s_posts:
        if r.get("state") != "live" or "편집 전 원본" in (r.get("tags") or ""):
            continue
        ref = s_ref(r)
        ev(r.get("create"), "Server", "메시지 작성", name(r.get("user")), f"[{name(r.get('channel'))}] {msg(r)}", ref)
        if r.get("edit"):
            ev(r.get("edit"), "Server", "메시지 편집", name(r.get("user")), f"[{name(r.get('channel'))}] {msg(r)}", ref)
        if r.get("delete"):
            ev(r.get("delete"), "Server", "메시지 삭제", name(r.get("user")), f"[{name(r.get('channel'))}] {msg(r)} ({r.get('tags')})", ref)
    for r in _rows(server, "audits"):
        ev(r.get("time"), "Server", "감사 로그", name(r.get("user")), f"{r.get('action')} {r.get('extra')} {r.get('ip')}",
           {"mode": "server", "section": "audits", "match": {"time": r.get("time"), "action": r.get("action"), "session": r.get("session")}})
    for r in sessions:
        client = f"{r.get('platform')} {r.get('os')} {r.get('browser')}".strip()
        ev(r.get("create"), "Server", "세션 생성", name(r.get("user")), ", ".join(x for x in (client, str(r.get("state"))) if x),
           {"mode": "server", "section": "sessions", "match": {"id": r.get("id")}})
    tl.sort(key=lambda r: parse_utc(r["time"]) or parse_utc("9999-12-31 00:00:00"))

    summary = [
        {"label": "교차 흔적", "value": findings_summary(out)},
        {"label": "캐시 메시지 대조", "value": f"{len(m_rows)}건 (일치 {counts['same']}, 편집 전 원문 {counts['older']}, "
                                             f"서버에서 지워짐 {counts['gone']}, 서버에 없음 {counts['missing']}, 불일치 {counts['diff']})"},
        {"label": "초안 → 서버 전송 확인", "value": f"{sent}건 (전송 기록 없음 {unsent})"},
        {"label": "로그인 계정", "value": login_user or "-"},
    ]
    if notes:
        summary.append({"label": "대조 못 한 항목", "value": " / ".join(notes)})
    sections = [
        findings_table("cross_findings", "교차 흔적", out,
                       "Client, Server 기록을 맞대어 찾은 삭제, 변조 정황입니다. 확실 = 두 기록으로 확인되는 사실, 추정 = 정황. "
                       "'서버에 없다'는 판단은 같은 서버이고 서버 기록이 캐시 시각 이후까지 있을 때만 확실로 둡니다. "
                       "행을 누르고 [근거 행으로 이동]으로 해당 증거의 원래 표를 엽니다."
                       + (" 대조 못 한 항목: " + " / ".join(notes) + "." if notes else ""), CROSS_COLS),
        table("cross_messages", "캐시 메시지 대조", [
            ("result", "대조 결과"), ("create", "작성 시각 (UTC)"), ("channel", "채널"), ("user", "작성자"),
            ("client", "클라이언트 캐시 내용"), ("server", "서버 현재 내용"), ("server_state", "서버 상태"),
            ("cached", "캐시 시각 (UTC)"), ("id", "post id"),
        ], m_rows, "클라이언트 캐시에서 복원한 메시지를 같은 post id 의 서버 posts 행(삭제, 이전 버전 포함)과 대조합니다.", row_class="_rc"),
        table("cross_drafts", "초안 ↔ 서버 메시지", [
            ("result", "대조 결과"), ("update", "초안 시각 (UTC)"), ("channel", "채널"), ("kind", "종류"), ("message", "초안 내용"),
            ("post", "서버 post id"), ("post_create", "서버 작성 시각 (UTC)"), ("post_user", "서버 작성자"), ("post_state", "서버 상태"),
        ], d_rows, "이 PC 에서 입력한 초안(IndexedDB)을 같은 채널, 같은 내용, 이 PC 로그인 계정이 쓴 서버 메시지와 맞춥니다 (초안 시각에서 하루 이내). "
                   "입력 중간 상태(뒤 초안의 앞부분)와 슬래시 명령은 '전송 기록 없음'에서 뺐습니다. "
                   "'전송 기록 없음'은 보내지 않았거나, 보낸 뒤 서버에서 행이 사라진 경우입니다.", row_class="_rc"),
        table("cross_account", "계정, 세션", [
            ("item", "항목"), ("client", "Client"), ("server", "Server"), ("judge", "판단"), ("certainty", "확실성"),
        ], acc_rows, "이 PC 가 어느 서버의 어느 계정, 세션으로 접속했는지 확인합니다. Mattermost 인증 쿠키 값은 OS 암호화(DPAPI)라 "
                     "토큰을 직접 비교할 수 없어, 쿠키 만료 시각과 서버 세션 만료 시각(같은 값으로 발급, 5초 이내)으로 맞춥니다. "
                     "맞는 세션이 없는 것은 로그아웃, 만료, 세션 연장으로도 생겨 흔적으로 올리지 않습니다."),
        table("cross_timeline", "통합 타임라인", [
            ("time", "시각 (UTC)"), ("side", "출처"), ("kind", "종류"), ("user", "사용자"), ("text", "내용"),
        ], tl, "Client(앱 저장소, 초안, 쿠키)와 Server(메시지, 감사 로그, 세션) 기록을 시간순으로 합쳤습니다. "
               "Client 앱 로그(main.log)는 PC 로컬 시각이라 넣지 않았습니다."),
    ]
    return {"summary": summary, "sections": sections}


class _Judge:
    def __init__(self, same_server: bool | None, server_times: list):
        ts = [t for t in (parse_utc(x) for x in server_times) if t]
        self.same_server, self.latest = same_server, (max(ts) if ts else None)

    def absence(self, when) -> tuple[str, str]:
        if self.same_server is not True:
            return INFERRED, (" 접속 서버 주소가 서버 설정과 달라 추정으로 둡니다." if self.same_server is False
                              else " 같은 서버인지 확인하지 못해(접속 서버 정보 없음) 추정으로 둡니다.")
        t = parse_utc(when)
        if self.latest is None or t is None:
            return INFERRED, " 서버, 클라이언트 시각을 비교할 수 없어 추정으로 둡니다."
        if t > self.latest:
            return INFERRED, f" 클라이언트 기록이 서버 기록의 마지막 시각({self.latest:%Y-%m-%d %H:%M:%S})보다 늦어, 서버 DB 가 더 이른 시점의 것일 수 있습니다."
        return CERTAIN, ""


def _server_match(site: str, c_urls: list[str], out: list, site_label: str, c_ref: dict | None) -> tuple[bool | None, dict]:
    s_host = _host(site)
    c_urls = [u for u in dict.fromkeys(c_urls) if u]
    same = any(_host(u) == s_host for u in c_urls) if s_host and c_urls else None
    if same is False:
        out.append(finding(INFERRED, "다른 서버 의심", "", "접속 서버",
                           f"클라이언트에 등록된 서버({', '.join(c_urls)})의 주소가 서버 설정 {site_label}({site})과 다릅니다. "
                           "IP, 도메인, 내부/외부 주소만 다른 같은 서버일 수 있습니다. 같은 서버가 아니면 대조는 의미가 없어, "
                           "이 경우 '없다'는 판단은 모두 추정으로 낮췄습니다.", f"접속 서버 ↔ {site_label}", c_ref))
    return same, {"item": "접속 서버", "client": ", ".join(c_urls), "server": f"{site} ({site_label})" if site else "",
                  "judge": {True: "일치", False: "불일치"}.get(same, "판단 불가 (정보 없음)"),
                  "certainty": CERTAIN if same is not None else "", "_ref": c_ref}


def _sections(out, notes, msg_tab, extra_tabs, acc_rows, tl, summary_extra):
    tl.sort(key=lambda r: parse_utc(r["time"]) or parse_utc("9999-12-31 00:00:00"))
    summary = [{"label": "교차 흔적", "value": findings_summary(out)}] + summary_extra
    if notes:
        summary.append({"label": "대조 못 한 항목", "value": " / ".join(notes)})
    return {"summary": summary, "sections": [
        findings_table("cross_findings", "교차 흔적", out,
                       "Client, Server 기록을 맞대어 찾은 삭제, 변조 정황입니다. 확실 = 두 기록으로 확인되는 사실, 추정 = 정황. "
                       "'서버에 없다'는 판단은 같은 서버이고 서버 기록이 클라이언트 기록 이후까지 있을 때만 확실로 둡니다. "
                       "행을 누르고 [근거 행으로 이동]으로 해당 증거의 원래 표를 엽니다."
                       + (" 대조 못 한 항목: " + " / ".join(notes) + "." if notes else ""), CROSS_COLS),
        *([msg_tab] if msg_tab else []),
        *extra_tabs,
        table("cross_account", "계정, 세션", [
            ("item", "항목"), ("client", "Client"), ("server", "Server"), ("judge", "판단"), ("certainty", "확실성"),
        ], acc_rows, "이 PC 가 어느 서버의 어느 계정, 세션으로 접속했는지 확인합니다. 맞는 세션, 토큰이 없는 것은 로그아웃, 만료로도 생겨 흔적으로 올리지 않습니다."),
        table("cross_timeline", "통합 타임라인", [
            ("time", "시각 (UTC)"), ("side", "출처"), ("kind", "종류"), ("user", "사용자"), ("text", "내용"),
        ], tl, "Client 와 Server 기록을 시간순으로 합쳤습니다. PC 로컬 시각으로만 남는 앱 로그는 넣지 않았습니다."),
    ]}


_RC_RANK = {"": 0, "softdel": 1, "deleted": 2, "updated": 3}


def _prefer_live(rows: list[dict], key: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in rows:
        k = str(r.get(key))
        if k not in out or _RC_RANK.get(r.get("_rc") or "", 4) < _RC_RANK.get(out[k].get("_rc") or "", 4):
            out[k] = r
    return out


def _ev(tl, time, side, kind, user, text, ref):
    if time and parse_utc(time):
        tl.append({"time": time, "side": side, "kind": kind, "user": user, "text": short(text, 200), "_ref": ref})


NARROW_MSG = re.compile(r"/(?:near|with|id)/(\d+)")
NARROW_CHAN = re.compile(r"/(?:channel|stream)/(\d+)-")
ID_IN = re.compile(r"\(id (\d+)\)")


def zulip(client: dict, server: dict) -> dict:
    out, notes, acc_rows, tl = [], [], [], []
    nm = lambda s: split_label(s)[0].split(" <")[0]
    uid_of = lambda s: (ID_IN.search(str(s or "")) or [None, ""])[1]
    if _section(server, "messages") is None:
        notes.append("서버 메시지를 해석하지 못해 메시지 대조를 하지 않았습니다")
    msgs = _rows(server, "messages")
    by_id: dict[str, list[dict]] = {}
    for r in msgs:
        by_id.setdefault(str(r.get("id")), []).append(r)
    streams = _prefer_live(_rows(server, "streams"), "id")

    def s_ref(r):
        return {"mode": "server", "section": "messages", "match": {"id": r.get("id"), "table": r.get("table"), "rid": r.get("rid")}}

    site = next((v for k, v in _kv(server, "server_info").items() if "EXTERNAL_HOST" in k), "")
    c_servers = _rows(client, "servers")
    c_ref = {"mode": "client", "section": "servers", "match": {"url": c_servers[0].get("url")}} if c_servers else None
    same, row = _server_match(site, [s.get("url") for s in c_servers], out, "EXTERNAL_HOST", c_ref)
    acc_rows.append(row)
    judge = _Judge(same, [r.get(k) for r in msgs for k in ("time", "edit")] + [r.get("time") for r in _rows(server, "requests")])

    sessions = {r.get("key"): r for r in _rows(server, "sessions") if r.get("key")}
    login_uids, login_names = [], []
    for ck in _rows(client, "cookies"):
        if not str(ck.get("name") or "").endswith("sessionid"):
            continue
        if not ck.get("value"):
            if ck.get("encrypted"):
                notes.append(f"세션 쿠키 {ck.get('name')} 가 OS 암호화돼 있어 서버 세션과 대조하지 못했습니다 (계정 특정, 요청 대조 불가)")
            continue
        s = sessions.get(ck["value"])
        acc_rows.append({
            "item": f"세션 쿠키 {ck.get('name')} ↔ django_session",
            "client": f"{ck.get('host')}, 생성 {ck.get('created')}, 만료 {ck.get('expires')}, 마지막 접근 {ck.get('last_access')}",
            "server": f"{s.get('user')}, 만료 {s.get('expire')}, {s.get('state')}" if s
            else ("(같은 session_key 없음 - 로그아웃, 만료로 지워졌을 수 있음)" if sessions else "(서버 세션 정보 없음)"),
            "judge": "같은 세션 (세션 키 일치)" if s else "대응 세션 없음", "certainty": CERTAIN if s else "",
            "_ref": {"mode": "server", "section": "sessions", "match": {"key": s.get("key")}} if s else None})
        if s and uid_of(s.get("user")):
            login_uids.append(uid_of(s.get("user")))
            login_names.append(nm(s.get("user")))
        _ev(tl, ck.get("created"), "Client", "로그인 쿠키 생성", "", f"{ck.get('host')} {ck.get('name')}",
            {"mode": "client", "section": "cookies", "match": {"name": ck.get("name"), "host": ck.get("host")}})
    login_uids, login_names = list(dict.fromkeys(login_uids)), list(dict.fromkeys(login_names))
    if not login_uids:
        acc_rows.append({"item": "로그인 계정", "client": "(세션 쿠키로 계정을 특정하지 못함)", "server": "", "judge": "판단 불가", "certainty": "", "_ref": None})

    v_rows = []
    for b in _rows(client, "breadcrumbs"):
        url = b.get("url") or ""
        if "#narrow" not in url:
            continue
        bref = {"mode": "client", "section": "breadcrumbs", "match": {"time": b.get("time"), "url": url}}
        for mid in NARROW_MSG.findall(url):
            vers = by_id.get(mid, [])
            cur = next((r for r in vers if r.get("table") == "zerver_message" and r.get("state") == "live"), None)
            arch = next((r for r in vers if r.get("table") == "zerver_archivedmessage" and r.get("state") == "live"), None)
            res = "live" if cur else ("삭제됨 (보관 테이블)" if arch else ("DB 에서 지워진 행만" if vers else "서버에 없음"))
            v_rows.append({"time": b.get("time"), "what": f"message {mid}", "url": url, "result": res,
                           "server": short((cur or arch or (vers[0] if vers else {})).get("content"), 120),
                           "_rc": "" if cur else ("softdel" if arch else "deleted"), "_ref": bref})
            if not has_messages(server):
                continue
            if arch:
                m = re.search(r"\((\d{4}-\d\d-\d\d [\d:.]+)\)", arch.get("tags") or "")
                first = _before(b.get("time"), m[1]) if m else None
                out.append(finding(CERTAIN if first and same is True else INFERRED, "삭제된 메시지를 이 PC 에서 연 기록", b.get("time"), f"message {mid}, {arch.get('conv')}",
                                   f"이 PC 앱의 화면 기록({b.get('time')})이 서버에서 삭제된 메시지를 가리킵니다"
                                   + (f" (삭제 {m[1]} 보다 앞섬)." if first else " (삭제 시각과 선후를 확인하지 못함).")
                                   + (" 같은 서버로 확인되지 않아 추정으로 둡니다." if same is not True else "")
                                   + f" 삭제된 내용: \"{short(arch.get('content'))}\"", "breadcrumb ↔ 메시지", s_ref(arch), "softdel"))
            elif not vers:
                cert, why = judge.absence(b.get("time"))
                out.append(finding(cert, "서버에 없는 메시지를 연 기록", b.get("time"), f"message {mid}",
                                   f"이 PC 앱의 화면 기록이 가리키는 메시지 id {mid} 가 서버 현재, 보관 테이블 어디에도 없습니다 - 완전 삭제됐을 수 있습니다.{why}",
                                   "breadcrumb ↔ 메시지", bref, "deleted"))
        for cid in NARROW_CHAN.findall(url):
            st = streams.get(cid)
            if not streams:
                res, rc = "판단 불가 (서버 채널 정보 없음)", "unknown"
            elif st is None:
                res, rc = "서버에 없음", "deleted"
            elif st.get("_rc") == "deleted":
                res, rc = "DB 에서 지워진 행만", "deleted"
            elif str(st.get("deactivated") or "").lower() not in ("", "none", "false"):
                res, rc = "보관된 채널", "softdel"
            else:
                res, rc = "live", ""
            v_rows.append({"time": b.get("time"), "what": f"채널 id {cid}", "url": url, "result": res,
                           "server": f"#{st.get('name')}" if st else "", "_rc": rc, "_ref": bref})
            if st is None and streams:
                cert, why = judge.absence(b.get("time"))
                out.append(finding(cert, "서버에 없는 채널을 연 기록", b.get("time"), f"채널 id {cid}",
                                   f"이 PC 앱의 화면 기록이 가리키는 채널 id {cid} 가 서버 zerver_stream 에 없습니다 (삭제된 행 포함).{why}",
                                   "breadcrumb ↔ 채널", bref, "deleted"))
        _ev(tl, b.get("time"), "Client", "앱 화면", ", ".join(login_names), f"{b.get('meaning')} {url}", bref)
    for b in _rows(client, "breadcrumbs"):
        if "#narrow" not in (b.get("url") or "") and b.get("meaning"):
            _ev(tl, b.get("time"), "Client", "앱 기록", ", ".join(login_names), f"{b.get('meaning')} {b.get('url') or ''}",
                {"mode": "client", "section": "breadcrumbs", "match": {"time": b.get("time"), "event": b.get("event")}})

    crumbs = sorted(((parse_utc(b.get("time")), b) for b in _rows(client, "breadcrumbs") if parse_utc(b.get("time"))), key=lambda x: x[0])
    r_rows = []
    for q in _rows(server, "requests"):
        if not (uid_of(q.get("user")) in login_uids and "ZulipElectron" in str(q.get("client") or "")):
            continue
        qref = {"mode": "server", "section": "requests", "match": {"time": q.get("time"), "path": q.get("path")}}
        q = {**q, "ip": q.get("ip") or "-"}
        r_rows.append({"time": q.get("time"), "method": q.get("method"), "meaning": q.get("meaning"), "path": q.get("path"),
                       "status": q.get("status"), "ip": q.get("ip"), "client": q.get("client"),
                       "_rc": {"DELETE": "deleted", "PATCH": "updated"}.get(q.get("method"), ""), "_ref": qref})
        if q.get("method") != "GET":
            _ev(tl, q.get("time"), "Server", "앱 요청 (server.log)", nm(q.get("user")), f"{q.get('method')} {q.get('meaning') or q.get('path')}, {q.get('ip')}", qref)
        m = re.match(r"메시지 (삭제) \(id (\d+)\)", q.get("meaning") or "")
        if m and str(q.get("status") or "").startswith("2"):
            t = parse_utc(q.get("time"))
            near = [b for bt, b in crumbs if t and 0 <= (t - bt).total_seconds() <= 120]
            target = next((r for r in by_id.get(m[2], []) if r.get("state") == "live"), None)
            out.append(finding(INFERRED, f"이 계정, 데스크톱 앱의 메시지 {m[1]} 요청", q.get("time"), f"message {m[2]}, {nm(q.get('user'))}, {q.get('ip')}",
                               f"server.log 에 이 PC 로그인 계정이 데스크톱 앱({q.get('client')}, IP {q.get('ip')})으로 보낸 {m[1]} 요청이 있습니다."
                               + (f" 대상 내용: \"{short(target.get('content'))}\"." if target else "")
                               + (f" 직전 2분 안의 이 PC 화면 기록: {near[-1].get('meaning')} ({near[-1].get('time')})." if near else "")
                               + " 같은 계정의 다른 PC 데스크톱 앱일 가능성 때문에 추정으로 둡니다.",
                               "요청 로그 ↔ 세션 쿠키", qref, "deleted" if m[1] == "삭제" else "updated"))
    for r in msgs:
        if uid_of(r.get("sender")) in login_uids and r.get("table") == "zerver_message" and r.get("state") == "live":
            _ev(tl, r.get("time"), "Server", "메시지 작성", nm(r.get("sender")), f"[{r.get('conv')}] {r.get('content')}", s_ref(r))

    d_rows = []
    by_text: dict[str, list[dict]] = {}
    for r in msgs:
        if not login_uids or uid_of(r.get("sender")) in login_uids:
            by_text.setdefault((r.get("content") or "").strip(), []).append(r)
    for d in _rows(client, "drafts"):
        text = (d.get("content") or "").strip()
        if not text:
            continue
        when = d.get("updated") or d.get("time")
        cands = by_text.get(text, [])
        if parse_utc(when):
            near = []
            for p in cands:
                g = _gap(p.get("time"), when)
                if g is None or g > 86400:
                    continue
                if _before(p.get("time"), when) and g > 60:
                    continue
                near.append((g, p))
            p = min(near, key=lambda x: x[0])[1] if near else None
        else:
            p = cands[0] if len(cands) == 1 else None
        res = ("서버에 전송 기록 없음" if not p else
               "전송 후 삭제 (보관 테이블)" if p.get("table") == "zerver_archivedmessage" else
               "전송 후 DB 에서 삭제" if p.get("_rc") == "deleted" else "전송됨")
        d_rows.append({"result": res, "update": when, "to": d.get("to"), "message": d.get("content"), "state": d.get("state"),
                       "post": p.get("id") if p else "", "post_time": p.get("time") if p else "",
                       "_rc": {"서버에 전송 기록 없음": "unknown", "전송됨": ""}.get(res, "deleted"),
                       "_ref": {"mode": "client", "section": "drafts", "match": {"draft_id": d.get("draft_id"), "seq": d.get("seq")}}})
        _ev(tl, when, "Client", "초안", ", ".join(login_names), f"[{d.get('to')}] {d.get('content')} → {res}", d_rows[-1]["_ref"])
    for r in _rows(server, "audit"):
        if uid_of(r.get("acting")) in login_uids or uid_of(r.get("modified")) in login_uids:
            _ev(tl, r.get("time"), "Server", "감사 로그", nm(r.get("acting")), f"{r.get('event')} {r.get('extra') or ''}",
                {"mode": "server", "section": "audit", "match": {"time": r.get("time"), "event": r.get("event")}})

    extra = [
        table("cross_views", "화면 기록 ↔ 서버", [
            ("time", "화면 기록 시각 (UTC)"), ("what", "가리킨 대상"), ("result", "서버 상태"), ("server", "서버 내용"), ("url", "화면 URL"),
        ], v_rows, "이 PC 앱의 화면 이동 기록(sentry breadcrumb 의 #narrow URL)이 가리키는 메시지, 채널이 서버에 지금 어떻게 남아 있는지 봅니다.", row_class="_rc"),
        table("cross_requests", "이 계정의 데스크톱 앱 요청", [
            ("time", "시각 (UTC)"), ("method", "메서드"), ("meaning", "해석"), ("status", "상태"), ("ip", "IP"), ("client", "클라이언트"), ("path", "경로"),
        ], r_rows, "server.log 에서 세션 쿠키로 특정한 이 PC 로그인 계정이 데스크톱 앱(ZulipElectron)으로 보낸 요청입니다. "
                   "같은 계정의 다른 PC 데스크톱 앱 요청도 섞일 수 있어 IP 로 구분해 보세요.", row_class="_rc"),
        table("cross_drafts", "초안 ↔ 서버 메시지", [
            ("result", "대조 결과"), ("update", "초안 시각 (UTC)"), ("to", "대상"), ("message", "초안 내용"), ("state", "초안 상태"),
            ("post", "서버 message id"), ("post_time", "서버 보낸 시각 (UTC)"),
        ], d_rows, "이 PC Local Storage 의 초안을 로그인 계정이 보낸 같은 내용의 서버 메시지와 맞춥니다.", row_class="_rc"),
    ]
    ips = sorted({r["ip"] for r in r_rows if r.get("ip") not in ("", "-")})
    return _sections(out, notes, None, extra, acc_rows, tl, [
        {"label": "로그인 계정", "value": ", ".join(login_names) or "-"},
        {"label": "데스크톱 앱 요청", "value": f"{len(r_rows)}건" + (f" (IP {', '.join(ips)})" if ips else "")},
        {"label": "화면 기록 대조", "value": f"{len(v_rows)}건 (서버에서 삭제, 없음 {sum(1 for r in v_rows if r['_rc'])})"},
    ])


def has_messages(server: dict) -> bool:
    return _section(server, "messages") is not None


FILE_ID = re.compile(r"id ([0-9a-f]{24}|[A-Za-z0-9]{17})\)")


def _rc_token_hash(token: str) -> str:
    import base64
    import hashlib
    return base64.b64encode(hashlib.sha256(token.encode()).digest()).decode()


def rocketchat(client: dict, server: dict) -> dict:
    out, notes, acc_rows, tl = [], [], [], []
    has_msgs = _section(server, "messages") is not None
    if not has_msgs:
        notes.append("서버 메시지를 해석하지 못해 메시지 대조를 하지 않았습니다")
    s_msgs = _rows(server, "messages")
    by_id: dict[str, list[dict]] = {}
    for r in s_msgs:
        by_id.setdefault(r.get("id"), []).append(r)
    s_users = {r.get("id"): r for r in _rows(server, "users")}
    s_rooms = _prefer_live(_rows(server, "rooms"), "id")
    s_uploads = _prefer_live(_rows(server, "uploads"), "id")

    def s_ref(r):
        return {"mode": "server", "section": "messages", "match": {"id": r.get("id"), "state": r.get("state"), "source": r.get("source")}}

    site = next((v for k, v in _kv(server, "settings").items() if k.split(" ")[0] == "Site_Url" or "Site_Url" in k), "")
    c_servers = _rows(client, "servers")
    c_ref = {"mode": "client", "section": "servers", "match": {"url": c_servers[0].get("url")}} if c_servers else None
    same, row = _server_match(site, [s.get("url") for s in c_servers], out, "Site_Url", c_ref)
    acc_rows.append(row)
    judge = _Judge(same, [r.get(k) for r in s_msgs for k in ("ts", "updated_at", "deleted_at")])

    ls = _rows(client, "localstorage")
    tokens_known = any("_tokens" in u for u in s_users.values())
    login_ids = []
    for r in ls:
        if r.get("key") == "Meteor.userId" and r.get("state") == "live" and r.get("value"):
            login_ids.append(str(r["value"]))
        if r.get("key") != "Meteor.loginToken" or not r.get("value") or r.get("state") == "deleted":
            continue
        h = _rc_token_hash(str(r["value"]))
        cur = next((u for u in s_users.values() if any(t.get("hash") == h for t in u.get("_tokens") or [])), None)
        old = None if cur else next(((u, t) for u in s_users.values() for t in u.get("_old_tokens") or [] if t.get("hash") == h), None)
        lref = {"mode": "client", "section": "localstorage", "match": {"key": "Meteor.loginToken", "seq": r.get("seq")}}
        if cur:
            when = next((t.get("when") for t in cur["_tokens"] if t.get("hash") == h), "")
            judge_txt, srv = "같은 토큰 (해시 일치)", f"{cur.get('username')} ({cur.get('id')}), 발급 {when}"
            login_ids.append(cur.get("id"))
        elif old:
            judge_txt, srv = "서버에서 제거된 토큰 (로그아웃, 강제 로그아웃, 정리)", f"{old[0].get('username')} ({old[0].get('id')}), 발급 {old[1].get('when')}, 이전 버전 문서에만 있음"
            login_ids.append(old[0].get("id"))
        else:
            judge_txt = "대응 토큰 없음" if tokens_known else "판단 불가 (Server 결과를 다시 분석하면 대조됨)"
            srv = "(users.services.resume 에 같은 hashedToken 없음)" if tokens_known else "(서버 결과에 토큰 해시 없음)"
        acc_rows.append({"item": f"로그인 토큰 Meteor.loginToken ({r.get('server')})", "client": f"sha256 base64 {h[:12]}…",
                         "server": srv, "judge": judge_txt, "certainty": CERTAIN if (cur or old) else "",
                         "_ref": {"mode": "server", "section": "users", "match": {"id": (cur or old[0]).get("id")}} if (cur or old) else lref})
    if not tokens_known and s_users:
        notes.append("Server 결과에 로그인 토큰 해시가 없어(이전 분석기) 토큰 대조를 못 했습니다 - Server 결과를 다시 분석하세요")
    login_ids = list(dict.fromkeys(login_ids))
    for uid in login_ids:
        u = s_users.get(uid)
        acc_rows.append({"item": "로그인 계정 (Meteor.userId)", "client": uid,
                         "server": f"{u.get('username')}, {u.get('emails')}, 마지막 로그인 {u.get('last_login') or '-'}" if u else "(서버 users 에 없음)",
                         "judge": "일치" if u else "서버에 없음", "certainty": CERTAIN if (u or s_users) else "",
                         "_ref": {"mode": "server", "section": "users", "match": {"id": uid}} if u else None})
        if not u and s_users:
            cert, why = (CERTAIN, "") if same is True else (INFERRED, " 같은 서버로 확인되지 않아 추정으로 둡니다.")
            out.append(finding(cert, "서버에 없는 계정", "", f"user {uid}",
                               "이 PC 의 로그인 사용자 id 가 서버 users 에 없습니다 (삭제된 문서 포함) - 계정 삭제 또는 다른 서버." + why,
                               "Local Storage ↔ 사용자", {"mode": "client", "section": "localstorage", "match": {"key": "Meteor.userId"}}))
    login_names = [s_users[u].get("username") for u in login_ids if u in s_users]

    m_rows, seen = [], set()
    cnt = {"same": 0, "e2e": 0, "older": 0, "deleted": 0, "missing": 0, "diff": 0}
    basis = "메시지 이력 ↔ 메시지"
    for c in (_rows(client, "messages") if has_msgs else []):
        cid, ctext, plain = c.get("id"), c.get("msg") or "", c.get("plain") or ""
        shown = plain or ctext or ""
        if c.get("files"):
            shown = (shown + " / 첨부: " if shown and shown != "(첨부만)" else "첨부: ") + str(c["files"]).replace("\n", ", ")
        key = (cid, shown)
        if not cid or key in seen:
            continue
        seen.add(key)
        tgt = f"message {cid}, {c.get('user')}, {c.get('room')}"
        c_ref = {"mode": "client", "section": "messages", "match": {"id": cid, "state": c.get("state")}}
        vers = by_id.get(cid, [])
        cur = next((r for r in vers if r.get("state") == "live"), None)
        dele = next((r for r in vers if r.get("_rc") == "deleted"), None)
        row = {"result": "", "ts": c.get("ts"), "room": c.get("room"), "user": c.get("user"), "client": shown,
               "server": (cur or dele or {}).get("msg") or ((cur or dele or {}).get("e2e") and "(E2E 암호문)") or "",
               "server_state": (cur or dele or {}).get("state", ""), "id": cid, "_rc": "", "_ref": c_ref}
        if not vers:
            cert, why = judge.absence(c.get("updated") or c.get("ts"))
            row.update(result="서버에 없음", _rc="deleted")
            cnt["missing"] += 1
            out.append(finding(cert, "서버에 없는 메시지", c.get("ts"), tgt,
                               f"클라이언트 IndexedDB lastMessage 에는 있지만 서버 message, 휴지통, oplog 어디에도 이 _id 가 없습니다. "
                               "서버에서 흔적 없이 지워졌을 수 있습니다 (oplog 가 잘려 삭제 기록이 밀려났거나, 다른 서버, 워크스페이스의 메시지일 수도 있음)."
                               f"{why} 내용: \"{short(shown)}\"", basis, c_ref, "deleted"))
        elif cur is None and dele is not None:
            row.update(result="서버에서 삭제된 메시지", _rc="deleted")
            cnt["deleted"] += 1
            e2e = bool(dele.get("e2e")) and bool(plain)
            out.append(finding(CERTAIN, "삭제된 메시지의 원문 (클라이언트 보유)", dele.get("deleted_at") or c.get("ts"), tgt,
                               (f"서버에서 {dele.get('deleted_at') or ''} 에 삭제된 E2E 메시지입니다. 서버에는 암호문만 남았지만 "
                                f"클라이언트가 방 키로 복호화한 평문: \"{short(shown, 160)}\"") if e2e else
                               f"서버에서 {dele.get('deleted_at') or ''} 에 삭제된 메시지를 이 PC 가 갖고 있습니다. 클라이언트 내용: \"{short(shown)}\"",
                               basis, s_ref(dele), "deleted"))
        elif cur is not None:
            if cur.get("e2e") or c.get("type") == "e2e":
                row["result"] = "E2E (존재만 확인)"
                cnt["e2e"] += 1
            elif (cur.get("msg") or "") == ctext:
                row["result"] = "일치"
                cnt["same"] += 1
            else:
                old = next((r for r in vers if r.get("_rc") == "updated" and (r.get("msg") or "") == ctext), None)
                if old is not None:
                    row.update(result="편집 전 원문 보유", _rc="updated")
                    cnt["older"] += 1
                    out.append(finding(CERTAIN if cur.get("edited") else INFERRED,
                                       "편집 전 원문 (클라이언트 보유)" if cur.get("edited") else "편집 표시 없는 변경 (클라이언트 원문 보유)",
                                       c.get("updated") or c.get("ts"), tgt,
                                       f"클라이언트 내용 \"{short(ctext)}\" 은 서버 이전 버전과 같고 서버 현재 내용은 \"{short(cur.get('msg'))}\" 입니다"
                                       + (f" (편집 {cur.get('edited')})." if cur.get("edited") else " - editedAt 이 없어 DB 직접 수정 가능성."),
                                       basis, s_ref(old), "updated"))
                elif ctext:
                    row.update(result="내용 불일치", _rc="deleted")
                    cnt["diff"] += 1
                    out.append(finding(INFERRED, "서버 기록과 다른 내용", c.get("updated") or c.get("ts"), tgt,
                                       f"같은 _id 인데 클라이언트 \"{short(ctext)}\" 이 서버 현재, 이전 버전 어느 것과도 같지 않습니다. 서버 현재 \"{short(cur.get('msg'))}\".",
                                       basis, s_ref(cur), "deleted"))
                else:
                    row["result"] = "일치 (본문 없음)"
                    cnt["same"] += 1
        for fid in FILE_ID.findall(c.get("files") or ""):
            u = s_uploads.get(fid)
            if u and u.get("_rc") == "deleted":
                out.append(finding(CERTAIN, "삭제된 첨부의 클라이언트 기록", u.get("deleted_at"), f"첨부 {u.get('name')} ({fid})",
                                   f"이 PC 의 lastMessage 에 남은 첨부가 서버에서 삭제됐습니다 (GridFS: {u.get('gridfs') or '정보 없음'}).",
                                   "메시지 이력 ↔ 첨부", {"mode": "server", "section": "uploads", "match": {"id": fid, "state": u.get("state")}}, "deleted"))
        m_rows.append(row)
        _ev(tl, c.get("ts"), "Client", "받은 메시지 (lastMessage)", c.get("user"), f"[{c.get('room')}] {shown}", c_ref)

    for r in _rows(client, "idb_rooms"):
        rid = r.get("rid")
        sr = s_rooms.get(rid)
        if (sr is None and s_rooms) or (sr and sr.get("_rc") == "deleted"):
            cert, why = (CERTAIN, "") if sr else judge.absence(r.get("updated"))
            out.append(finding(cert, "서버에서 사라진 방", r.get("updated"), f"방 {r.get('name') or r.get('members')} ({rid})",
                               ("이 PC 가 아는 방이 서버에서 삭제됐습니다." if sr else "이 PC 가 아는 방이 서버 rooms 에 없습니다 (삭제 문서 포함).") + why,
                               "IndexedDB 방 ↔ 방", {"mode": "client", "section": "idb_rooms", "match": {"rid": rid}}, "deleted"))

    for r in ls:
        if r.get("time") and r.get("meaning"):
            _ev(tl, r.get("time"), "Client", "앱 저장소 " + ("삭제" if r.get("state") == "deleted" else "기록"), ", ".join(login_names),
                f"{r.get('meaning')}: {r.get('key')}", {"mode": "client", "section": "localstorage", "match": {"key": r.get("key"), "seq": r.get("seq")}})
    for r in s_msgs:
        if r.get("state") == "live":
            _ev(tl, r.get("ts"), "Server", "메시지", r.get("user"), f"[{r.get('room')}] {r.get('msg') or ('(E2E 암호문)' if r.get('e2e') else r.get('files'))}", s_ref(r))
        elif r.get("_rc") == "deleted":
            _ev(tl, r.get("deleted_at"), "Server", "메시지 삭제", r.get("user"), f"[{r.get('room')}] {r.get('msg') or '(E2E 암호문)'}", s_ref(r))
    for r in _rows(server, "server_events"):
        if r.get("t") == "login" or (r.get("user") in login_names):
            _ev(tl, r.get("ts"), "Server", f"서버 이벤트 ({r.get('t')})", r.get("user"), f"{r.get('data') or ''} {r.get('ip') or ''}",
                {"mode": "server", "section": "server_events", "match": {"ts": r.get("ts"), "t": r.get("t")}})

    msg_tab = table("cross_messages", "메시지 대조", [
        ("result", "대조 결과"), ("ts", "보낸 시각 (UTC)"), ("room", "방"), ("user", "보낸 사람"), ("client", "클라이언트 내용 (E2E 는 복호화 평문)"),
        ("server", "서버 내용"), ("server_state", "서버 상태"), ("id", "_id"),
    ], m_rows, "클라이언트 IndexedDB 의 lastMessage 이력(모든 판)을 같은 _id 의 서버 메시지(현재, 이전 버전, 휴지통, oplog)와 대조합니다. "
               "E2E 메시지는 서버에 암호문만 있어 존재 여부만 대조하고, 서버에서 지워진 E2E 메시지는 클라이언트 평문을 보여 줍니다.", row_class="_rc")
    return _sections(out, notes, msg_tab, [], acc_rows, tl, [
        {"label": "메시지 대조", "value": f"{len(m_rows)}건 (일치 {cnt['same']}, E2E {cnt['e2e']}, 편집 전 원문 {cnt['older']}, "
                                        f"서버에서 삭제 {cnt['deleted']}, 서버에 없음 {cnt['missing']}, 불일치 {cnt['diff']})"},
        {"label": "로그인 계정", "value": ", ".join(login_names) or "-"},
    ])


CROSS = {"mattermost": mattermost, "zulip": zulip, "rocketchat": rocketchat}


def supported() -> list[str]:
    return list(CROSS)


def analyze(app: str, client: dict, server: dict) -> dict:
    return CROSS[app](client, server)

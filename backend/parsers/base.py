import re
from datetime import datetime, timedelta, timezone
from pathlib import Path


def table(id: str, title: str, columns: list[tuple[str, str]], rows: list[dict],
          description: str = "", row_class: str = "") -> dict:
    sec = {
        "id": id,
        "title": title,
        "type": "table",
        "description": description,
        "columns": [{"key": k, "label": label} for k, label in columns],
        "rows": rows,
    }
    if row_class:
        sec["row_class"] = row_class
    return sec


def kv(id: str, title: str, items: dict, description: str = "") -> dict:
    return {
        "id": id,
        "title": title,
        "type": "kv",
        "description": description,
        "rows": [{"key": k, "value": v} for k, v in items.items()],
    }


def pg_browser(id: str, title: str, description: str = "") -> dict:
    return {"id": id, "title": title, "type": "pgbrowser", "description": description, "rows": []}


CERTAIN, INFERRED = "확실", "추정"

FINDING_COLS = [("certainty", "확실성"), ("category", "분류"), ("time", "시각 (UTC)"), ("target", "대상"),
                ("detail", "내용"), ("basis", "근거")]


def finding(certainty: str, category: str, time: str, target: str, detail: str,
            basis: str = "", ref: dict | None = None, rc: str = "") -> dict:
    return {"certainty": certainty, "category": category, "time": time or "", "target": target,
            "detail": detail, "basis": basis, "_rc": rc, "_ref": ref}


def findings_table(id: str, title: str, rows: list[dict], description: str,
                   columns: list[tuple[str, str]] | None = None) -> dict:
    rows = sorted(rows, key=lambda r: (parse_utc(r.get("time")) or datetime.max, r.get("certainty") != CERTAIN))
    return table(id, title, columns or FINDING_COLS, rows, description, row_class="_rc")


_LABEL_RE = re.compile(r"^(.*?)\s*\(([^()]+)\)$")


def split_label(s) -> tuple[str, str]:
    s = str(s or "")
    m = _LABEL_RE.match(s)
    return (m[1], m[2]) if m else (s, s)


def parse_utc(s) -> datetime | None:
    if not isinstance(s, str) or not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def short(s, n: int = 80) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1] + "…"


def findings_summary(rows: list[dict]) -> str:
    n = sum(1 for r in rows if r.get("certainty") == CERTAIN)
    return f"{len(rows)}건 (확실 {n}, 추정 {len(rows) - n})"


def error_section(id: str, title: str, err: Exception | str) -> dict:
    return kv(id, title, {"분석 실패": str(err)}, "이 항목은 해석하지 못했습니다. 원본 파일은 '파일 목록'에서 확인할 수 있습니다.")


_EPOCH_1601 = datetime(1601, 1, 1)


def fmt_dt(dt: datetime | None, ms: bool = True) -> str:
    if not dt:
        return ""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    s = dt.strftime("%Y-%m-%d %H:%M:%S")
    return s + f".{dt.microsecond // 1000:03d}" if ms else s


def fmt_ms(v) -> str:
    try:
        v = int(v)
    except (TypeError, ValueError):
        return ""
    if v <= 0:
        return ""
    try:
        return fmt_dt(datetime(1970, 1, 1) + timedelta(milliseconds=v))
    except OverflowError:
        return str(v)


def fmt_webkit(us) -> str:
    try:
        us = int(us)
    except (TypeError, ValueError):
        return ""
    if us <= 0:
        return ""
    try:
        return fmt_dt(_EPOCH_1601 + timedelta(microseconds=us))
    except OverflowError:
        return str(us)


class BaseParser:
    mode: str = ""
    app: str = ""
    is_dummy: bool = True

    FINDINGS_DESC = ""

    def parse(self, root: Path, inventory: list[dict]) -> dict:
        raise NotImplementedError

    def findings(self, sections: list[dict]) -> list[dict]:
        raise NotImplementedError

    def run(self, root: Path, inventory: list[dict]) -> dict:
        result = self.parse(root, inventory)
        sections = result.get("sections", [])
        summary = result.get("summary", [])
        if type(self).findings is not BaseParser.findings:
            try:
                self.findings_notes = []
                rows = self.findings(sections)
                desc = self.FINDINGS_DESC
                if self.findings_notes:
                    desc += " 점검하지 못한 항목: " + " / ".join(self.findings_notes) + "."
                sections.insert(0, findings_table("findings", "삭제, 변조 흔적", rows, desc))
                summary = [{"label": "삭제, 변조 흔적", "value": findings_summary(rows)}] + summary
            except Exception as e:
                sections.insert(0, error_section("findings", "삭제, 변조 흔적", e))
        sections.append(table(
            "inventory", "파일 목록",
            [("path", "경로(ZIP 원본)"), ("size", "크기(byte)"), ("modified", "수정 시각(ZIP, 로컬)"), ("note", "비고")],
            inventory,
            "업로드된 ZIP 내부의 실제 파일 목록입니다. 파일명이 치환되었거나 추출되지 않은 항목은 비고에 표시됩니다.",
        ))
        extras = {k: v for k, v in result.items() if k not in ("summary", "sections")}
        return {
            **extras,
            "summary": summary,
            "sections": sections,
            "is_dummy": self.is_dummy,
        }

import hashlib
import json
import logging
import lzma
import os
import re
import shutil
import time
import uuid
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

WORKSPACE = Path(os.environ.get("MFA_WORKSPACE") or Path(__file__).resolve().parent.parent / "workspace") / "cases"

MAX_UPLOAD_BYTES = 4 * 1024**3
MAX_EXTRACT_BYTES = 20 * 1024**3
MAX_ENTRIES = 500_000
CHUNK = 1024 * 1024

_CASE_ID_RE = re.compile(r"[0-9a-f]{32}")
_WIN_INVALID = re.compile(r'[<>:"|?*\x00-\x1f]')
_WIN_RESERVED = re.compile(r"(CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³])(\..*)?", re.IGNORECASE)


class StorageError(Exception):
    pass


class NotFoundError(StorageError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fs(p: Path) -> str:
    s = str(p)
    if os.name == "nt" and not s.startswith("\\\\?\\"):
        return "\\\\?\\" + s
    return s


def _write_json_atomic(path: Path, data: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _move_dir(src: Path, dst: Path) -> None:
    delay, waited = 0.2, 0.0
    while True:
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if waited >= 60:
                raise
            log.warning("폴더 이동 재시도 (%.1fs): %s -> %s", waited, src, dst)
            time.sleep(delay)
            waited += delay
            delay = min(delay * 2, 5.0)


def _case_dir(case_id: str) -> Path:
    if not _CASE_ID_RE.fullmatch(case_id):
        raise StorageError("잘못된 케이스 ID입니다.")
    return WORKSPACE / case_id


def evidence_dir(case_id: str, mode: str, app: str) -> Path:
    return _case_dir(case_id) / mode / app


def create_case(name: str | None = None) -> dict:
    case_id = uuid.uuid4().hex
    d = _case_dir(case_id)
    d.mkdir(parents=True)
    case = {"id": case_id, "name": name or f"Case-{case_id[:8]}", "created_at": now_iso()}
    _write_json_atomic(d / "case.json", case)
    return case


def load_case(case_id: str) -> dict:
    f = _case_dir(case_id) / "case.json"
    if not f.exists():
        raise NotFoundError("케이스를 찾을 수 없습니다.")
    return json.loads(f.read_text(encoding="utf-8"))


def list_evidences(case_id: str) -> list[dict]:
    out = []
    for meta_file in sorted(_case_dir(case_id).glob("*/*/meta.json")):
        if meta_file.parts[-3].startswith("."):
            continue
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if not (isinstance(meta, dict) and meta.get("mode") and meta.get("app")):
                raise ValueError("필수 키 누락")
            if not isinstance(meta.get("evidence"), dict):
                meta["evidence"] = {}
            out.append(meta)
        except (OSError, ValueError) as e:
            log.warning("손상된 meta.json 무시: %s (%s)", meta_file, e)
    return out


def list_cases(limit: int = 10) -> list[dict]:
    if not WORKSPACE.exists():
        return []
    cases = []
    for d in WORKSPACE.iterdir():
        if not (d.is_dir() and _CASE_ID_RE.fullmatch(d.name)):
            continue
        try:
            case = load_case(d.name)
            evidences = list_evidences(d.name)
            times = [case.get("created_at"), *(e["evidence"].get("uploaded_at") for e in evidences)]
            cases.append({
                **case,
                "updated_at": max((t for t in times if isinstance(t, str)), default=""),
                "evidences": [{"mode": e["mode"], "app": e["app"]} for e in evidences],
            })
        except Exception as e:
            log.warning("손상된 케이스 무시: %s (%s)", d, e)
    cases.sort(key=lambda c: c["updated_at"], reverse=True)
    return cases[:limit]


def new_staging(case_id: str) -> Path:
    d = _case_dir(case_id) / ".staging" / uuid.uuid4().hex
    d.mkdir(parents=True)
    return d


def discard(path: Path) -> None:
    shutil.rmtree(_fs(path), ignore_errors=True)


def commit_staging(case_id: str, mode: str, app: str, staging: Path) -> None:
    final = evidence_dir(case_id, mode, app)
    final.parent.mkdir(parents=True, exist_ok=True)
    trash = None
    if final.exists():
        trash = staging.parent / f"old-{uuid.uuid4().hex}"
        _move_dir(final, trash)
    try:
        _move_dir(staging, final)
    except OSError:
        if trash:
            _move_dir(trash, final)
        raise
    if trash:
        discard(trash)


async def save_upload(upload_file, dest: Path) -> dict:
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    size = 0
    with dest.open("wb") as f:
        while chunk := await upload_file.read(CHUNK):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                raise StorageError("업로드 용량 제한(4GB)을 초과했습니다.")
            md5.update(chunk)
            sha256.update(chunk)
            f.write(chunk)
    return {"size": size, "md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def _sanitize_parts(name: str) -> list[str] | None:
    parts = []
    for p in re.split(r"[\\/]+", name):
        if p in ("", "."):
            continue
        if p == "..":
            return None
        p = _WIN_INVALID.sub("_", p)
        if _WIN_RESERVED.fullmatch(p):
            p = "_" + p
        if p[-1] in ". ":
            p = p[:-1] + "_"
        parts.append(p)
    return parts


def safe_extract(zip_path: Path, dest: Path) -> list[dict]:
    if not zipfile.is_zipfile(zip_path):
        raise StorageError("올바른 ZIP 파일이 아닙니다.")

    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    inventory = []
    used: dict[str, str] = {}
    total = 0

    try:
        zf = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as e:
        raise StorageError(f"ZIP 파일을 열 수 없습니다: {e}")

    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ENTRIES:
            raise StorageError(f"ZIP 엔트리 수 제한({MAX_ENTRIES:,}개)을 초과했습니다.")

        for info in infos:
            parts = _sanitize_parts(info.filename)
            if parts is None:
                raise StorageError(f"허용되지 않은 경로가 포함되어 있습니다: {info.filename}")
            if not parts:
                continue
            target = root.joinpath(*parts)
            if not target.is_relative_to(root):
                raise StorageError(f"허용되지 않은 경로가 포함되어 있습니다: {info.filename}")
            if info.is_dir():
                os.makedirs(_fs(target), exist_ok=True)
                continue

            entry = {
                "path": info.filename,
                "size": info.file_size,
                "modified": "%04d-%02d-%02d %02d:%02d:%02d" % info.date_time,
                "note": "",
            }
            inventory.append(entry)

            rel = "/".join(parts)
            if used.get(rel.lower()):
                stem = rel
                n = 1
                while used.get(f"{stem}~dup{n}".lower()):
                    n += 1
                rel = f"{stem}~dup{n}"
                target = root / rel
                entry["note"] = "중복 이름 → "
            if rel != info.filename.rstrip("/"):
                entry["note"] += f"저장 경로: {rel}"
            if info.flag_bits & 0x1:
                entry["note"] = "암호화된 엔트리 - 추출 생략"
                continue

            total += info.file_size
            if total > MAX_EXTRACT_BYTES:
                raise StorageError("압축 해제 용량 제한을 초과했습니다.")

            created = False
            try:
                os.makedirs(_fs(target.parent), exist_ok=True)
                with zf.open(info) as src, open(_fs(target), "xb") as dst:
                    created = True
                    shutil.copyfileobj(src, dst, CHUNK)
            except (zipfile.BadZipFile, zlib.error, lzma.LZMAError, EOFError, OSError,
                    NotImplementedError, RuntimeError) as e:
                if created:
                    try:
                        os.remove(_fs(target))
                    except OSError:
                        pass
                entry["note"] = f"추출 실패: {type(e).__name__}"
                log.warning("엔트리 추출 실패 %s: %s", info.filename, e)
                continue
            used[rel.lower()] = "f"
            try:
                ts = time.mktime(info.date_time + (0, 0, -1))
                os.utime(_fs(target), (ts, ts))
            except (OSError, ValueError, OverflowError):
                entry["note"] = (entry["note"] + " / " if entry["note"] else "") + "수정 시각 복원 실패"
    return inventory


def save_result(dir: Path, result: dict) -> None:
    _write_json_atomic(dir / "result.json", result)
    _write_json_atomic(dir / "meta.json", {
        "mode": result["mode"],
        "app": result["app"],
        "status": result["status"],
        "evidence": result["evidence"],
    })


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(_fs(path), "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def load_result(case_id: str, mode: str, app: str) -> dict:
    f = evidence_dir(case_id, mode, app) / "result.json"
    if not f.exists():
        raise NotFoundError("분석 결과가 없습니다.")
    return json.loads(f.read_text(encoding="utf-8"))


def delete_case(case_id: str) -> None:
    d = _case_dir(case_id)
    if not d.exists():
        raise NotFoundError("케이스를 찾을 수 없습니다.")
    trash = WORKSPACE / f".trash-{case_id}-{uuid.uuid4().hex[:8]}"
    _move_dir(d, trash)
    discard(trash)


def delete_evidence(case_id: str, mode: str, app: str) -> None:
    d = evidence_dir(case_id, mode, app)
    if d.exists():
        trash = _case_dir(case_id) / ".staging" / f"old-{uuid.uuid4().hex}"
        trash.parent.mkdir(parents=True, exist_ok=True)
        _move_dir(d, trash)
        discard(trash)

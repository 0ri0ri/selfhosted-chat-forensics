import hashlib
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend import storage
from backend.apps_meta import APPS
from backend.main import _analyze
from scripts import make_samples

SAMPLES = ROOT / "samples"
ALL = [(m, a) for m in ("client", "server") for a in ("mattermost", "zulip", "rocketchat")]

DEMO = [
    ("2026-002 연구실 PC", [("client", "zulip")]),
    (None, []),
    ("2026-003 Ops 서버 침해", ALL),
    ("2026-001 내부 유출 의심", [("client", "mattermost"), ("client", "rocketchat"), ("server", "mattermost")]),
]


def upload(case_id: str, mode: str, app: str) -> None:
    src = SAMPLES / f"{mode}_{app}.zip"
    staging = storage.new_staging(case_id)
    try:
        shutil.copyfile(src, staging / "evidence.zip")
        data = (staging / "evidence.zip").read_bytes()
        inventory, parsed = _analyze(mode, app, staging)
        result = {
            **parsed,
            "mode": mode,
            "app": app,
            "app_name": APPS[app]["name"],
            "status": "done",
            "evidence": {
                "filename": src.name,
                "size": len(data),
                "md5": hashlib.md5(data).hexdigest(),
                "sha256": hashlib.sha256(data).hexdigest(),
                "file_count": len(inventory),
                "uploaded_at": storage.now_iso(),
            },
        }
        storage.save_result(staging, result)
        storage.commit_staging(case_id, mode, app, staging)
    except Exception:
        storage.discard(staging)
        raise


def main() -> None:
    names = {c["name"] for c in storage.list_cases(limit=10_000)}
    first_run = not any(name in names for name, _ in DEMO if name)
    todo = [(n, u) for n, u in DEMO if (n is None and first_run) or (n is not None and n not in names)]
    if not todo:
        print("데모 케이스가 모두 있어 건너뜁니다.")
        return
    if not all((SAMPLES / f"{m}_{a}.zip").exists() for m, a in ALL):
        make_samples.main()

    for i, (name, uploads) in enumerate(todo):
        if i:
            time.sleep(1.1)
        case = storage.create_case(name)
        for mode, app in uploads:
            upload(case["id"], mode, app)
        print(f"생성: {case['name']} ({len(uploads)}개 업로드)")


if __name__ == "__main__":
    main()

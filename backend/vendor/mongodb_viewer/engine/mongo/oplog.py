"""oplog(local.oplog.rs) 해석과 문서 버전 재구성.

oplog 항목: op(i 입력, u 갱신, d 삭제, c 명령, n 없음), ns, ui, o, o2, ts, wall, lsid/txnNumber [문서: MongoDB Replica Set Oplog].
트랜잭션은 op=c, o.applyOps=[...] 안에 하위 연산이 들어 있다.
갱신의 o 는 MongoDB 5.0 이후 {"$v": 2, "diff": {...}} 형식이다 (u: 바꿈, i: 추가, d: 삭제, s<필드>: 하위 diff,
배열 하위 diff 는 a: true 와 u<번호>/s<번호>/l(새 길이)) [문서: MongoDB 소스 doc_diff]. 옛 $set/$unset 형식과
전체 치환(연산자 없는 문서)도 처리한다. 해석하지 못한 갱신은 그 문서의 재구성을 멈추고 이유를 남긴다.
"""

from __future__ import annotations

from .bsonlib import Date, Timestamp, canonical


def _copy(v):
    if isinstance(v, dict):
        return {k: _copy(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_copy(x) for x in v]
    return v


class DiffError(ValueError):
    pass


def apply_v2(doc: dict, diff: dict) -> dict:
    out = doc
    for k, v in diff.items():
        if k == "d":
            for f in v:
                out.pop(f, None)
        elif k in ("u", "i"):
            for f, val in v.items():
                out[f] = _copy(val)
        elif k.startswith("s") and len(k) > 1:
            f = k[1:]
            if not isinstance(v, dict):
                raise DiffError(f"하위 diff 형식 오류: {k}")
            if v.get("a") is True:
                cur = out.get(f)
                if not isinstance(cur, list):
                    raise DiffError(f"배열 diff 인데 대상이 배열이 아님: {f}")
                out[f] = _apply_array(cur, v)
            else:
                cur = out.get(f)
                if not isinstance(cur, dict):
                    raise DiffError(f"객체 diff 인데 대상이 객체가 아님: {f}")
                out[f] = apply_v2(cur, v)
        else:
            raise DiffError(f"알 수 없는 diff 키: {k}")
    return out


def _apply_array(arr: list, diff: dict) -> list:
    arr = list(arr)
    if "l" in diff:
        n = int(diff["l"])
        arr = arr[:n] + [None] * max(0, n - len(arr))
    for k, v in diff.items():
        if k in ("a", "l"):
            continue
        if k[0] == "u" and k[1:].isdigit():
            i = int(k[1:])
            while len(arr) <= i:
                arr.append(None)
            arr[i] = _copy(v)
        elif k[0] == "s" and k[1:].isdigit():
            i = int(k[1:])
            if i >= len(arr):
                raise DiffError(f"배열 하위 diff 위치 없음: {i}")
            if isinstance(v, dict) and v.get("a") is True:
                if not isinstance(arr[i], list):
                    raise DiffError(f"배열 diff 인데 원소가 배열이 아님: {i}")
                arr[i] = _apply_array(arr[i], v)
            elif isinstance(arr[i], dict):
                arr[i] = apply_v2(arr[i], v)
            else:
                raise DiffError(f"배열 원소 하위 diff 대상이 객체가 아님: {i}")
        else:
            raise DiffError(f"알 수 없는 배열 diff 키: {k}")
    return arr


def _set_path(doc: dict, path: str, val, unset=False):
    parts = path.split(".")
    cur = doc
    for p in parts[:-1]:
        if isinstance(cur, list) and p.isdigit():
            cur = cur[int(p)]
        else:
            cur = cur.setdefault(p, {})
    last = parts[-1]
    if isinstance(cur, list) and last.isdigit():
        i = int(last)
        if unset:
            if i < len(cur):
                cur[i] = None
        else:
            while len(cur) <= i:
                cur.append(None)
            cur[i] = _copy(val)
    elif unset:
        cur.pop(last, None)
    else:
        cur[last] = _copy(val)


def apply_update(doc: dict | None, o: dict) -> dict:
    """갱신 하나를 적용한 새 문서. doc 이 None 이면 전체 치환만 가능."""
    if o.get("$v") == 2 and not isinstance(o.get("diff"), dict):
        raise DiffError("$v:2 갱신인데 diff 가 없음")
    if o.get("$v") == 2:
        if doc is None:
            raise DiffError("이전 문서가 없어 diff 를 적용할 수 없음 (oplog 앞부분이 잘렸을 수 있음)")
        return apply_v2(_copy(doc), o["diff"])
    ops = [k for k in o if k.startswith("$") and k != "$v"]
    if not ops:
        return _copy(o)                       # 전체 치환
    if doc is None:
        raise DiffError("이전 문서가 없어 갱신을 적용할 수 없음")
    out = _copy(doc)
    for k in ops:
        if k == "$set":
            for p, v in o[k].items():
                _set_path(out, p, v)
        elif k == "$unset":
            for p in o[k]:
                _set_path(out, p, None, unset=True)
        else:
            raise DiffError(f"지원하지 않는 갱신 연산자 {k}")
    return out


def flatten(entries):
    """oplog 문서들 → 하위 연산까지 펼친 이벤트. entries: [(recordId, doc)] (ts 순).

    트랜잭션: applyOps 안의 하위 연산을 펼친다. prepared 트랜잭션(applyOps + prepare:true)은
    같은 세션, 트랜잭션 번호의 commitTransaction 이 나올 때만 적용하고, abortTransaction 이면 버린다
    [문서: MongoDB 트랜잭션 oplog 형식]. 여러 항목으로 나뉜 큰 트랜잭션(partialTxn)은 applyOps 를 차례로 펼친다.
    """
    out, pending = [], {}
    for rid, d in entries:
        ts = d.get("ts")
        wall = d.get("wall")
        base = {"recordId": rid, "ts": (ts.t, ts.i) if isinstance(ts, Timestamp) else None,
                "wall": wall.ms if isinstance(wall, Date) else None,
                "txn": d.get("txnNumber"), "has_lsid": "lsid" in d}
        txkey = (canonical(d.get("lsid")), d.get("txnNumber")) if "lsid" in d else None
        o = d.get("o")
        if d.get("op") == "c" and isinstance(o, dict):
            if isinstance(o.get("applyOps"), list):
                subs = [{**base, "sub": k, "op": s.get("op"), "ns": s.get("ns"), "ui": s.get("ui"),
                         "o": s.get("o"), "o2": s.get("o2")} for k, s in enumerate(o["applyOps"]) if isinstance(s, dict)]
                if o.get("prepare") and txkey:
                    pending[txkey] = subs            # 커밋 기록이 나올 때까지 보류
                else:
                    out.extend(subs)
                continue
            if "commitTransaction" in o and txkey in pending:
                for s in pending.pop(txkey):
                    out.append({**s, "commit_wall": base["wall"]})
            elif "abortTransaction" in o and txkey in pending:
                pending.pop(txkey)
        out.append({**base, "sub": None, "op": d.get("op"), "ns": d.get("ns"), "ui": d.get("ui"),
                    "o": o, "o2": d.get("o2")})
    return out


def target_id(ev):
    if ev["op"] == "u":
        o2 = ev.get("o2") or {}
        return o2.get("_id") if isinstance(o2, dict) else None
    o = ev.get("o") or {}
    return o.get("_id") if isinstance(o, dict) else None


def versions_by_id(events: list[dict]) -> dict:
    """한 컬렉션의 이벤트 → {id_key: {"versions": [{doc, ev, kind}], "deleted": ev|None, "problem": str|None,
    "inserted": ev|None, "id": _id}}"""
    out = {}
    for ev in events:
        if ev["op"] not in ("i", "u", "d"):
            continue
        _id = target_id(ev)
        if _id is None:
            continue
        key = canonical(_id)
        st = out.setdefault(key, {"id": _id, "versions": [], "deleted": None, "inserted": None, "problem": None,
                                  "events": []})
        st["events"].append(ev)
        if st["problem"]:
            continue
        try:
            if ev["op"] == "i":
                st["versions"].append({"doc": _copy(ev["o"]), "ev": ev, "kind": "insert"})
                st["inserted"] = st["inserted"] or ev
                st["deleted"] = None
            elif ev["op"] == "u":
                prev = st["versions"][-1]["doc"] if st["versions"] and not st["deleted"] else None
                st["versions"].append({"doc": apply_update(prev, ev["o"] or {}), "ev": ev, "kind": "update"})
            else:
                st["deleted"] = ev
        except Exception as e:                    # 재구성 실패는 그 문서만 멈추고 이유를 남긴다
            st["problem"] = f"{type(e).__name__}: {e}"
    return out

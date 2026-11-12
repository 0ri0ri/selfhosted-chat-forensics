"""BSON 디코더 (bsonspec.org 1.1). 표준 라이브러리만 쓴다.

decode() 는 파이썬 값으로, 타입을 잃지 않도록 BSON 고유 타입은 아래 클래스로 돌려준다.
elements() 는 최상위 요소의 바이트 위치(헥스 강조용)를 돌려준다.
to_json() 은 화면/내보내기용 확장 JSON(relaxed)으로 바꾼다. 큰 바이너리는 앞부분만 싣는다.
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import struct
import uuid as _uuid


class BSONError(ValueError):
    pass


class ObjectId:
    __slots__ = ("raw",)

    def __init__(self, raw: bytes):
        self.raw = bytes(raw)

    def __str__(self):
        return self.raw.hex()

    def __eq__(self, o):
        return isinstance(o, ObjectId) and o.raw == self.raw

    def __hash__(self):
        return hash(self.raw)

    def time(self) -> int:
        """앞 4바이트 = 생성 시각 (Unix 초, 빅엔디언) [문서: MongoDB ObjectId]."""
        return int.from_bytes(self.raw[:4], "big")


class Binary:
    __slots__ = ("data", "subtype")

    def __init__(self, data: bytes, subtype: int):
        self.data, self.subtype = bytes(data), subtype

    def __eq__(self, o):
        return isinstance(o, Binary) and o.data == self.data and o.subtype == self.subtype

    def __hash__(self):
        return hash((self.data, self.subtype))


class Date:
    __slots__ = ("ms",)

    def __init__(self, ms: int):
        self.ms = ms

    def __eq__(self, o):
        return isinstance(o, Date) and o.ms == self.ms

    def __hash__(self):
        return hash(self.ms)

    def iso(self) -> str:
        try:
            d = _dt.datetime(1970, 1, 1) + _dt.timedelta(milliseconds=self.ms)
            return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"
        except (OverflowError, ValueError):
            return str(self.ms)


class Timestamp:
    __slots__ = ("t", "i")

    def __init__(self, t: int, i: int):
        self.t, self.i = t, i

    def __eq__(self, o):
        return isinstance(o, Timestamp) and (o.t, o.i) == (self.t, self.i)

    def __hash__(self):
        return hash((self.t, self.i))


class Other:
    """Regex, Decimal128, Code, MinKey/MaxKey, 비권장 타입 등."""
    __slots__ = ("kind", "value")

    def __init__(self, kind: str, value):
        self.kind, self.value = kind, value

    def __eq__(self, o):
        return isinstance(o, Other) and (o.kind, o.value) == (self.kind, self.value)

    def __hash__(self):
        return hash((self.kind, str(self.value)))


TYPE_NAMES = {0x01: "double", 0x02: "string", 0x03: "object", 0x04: "array", 0x05: "binData", 0x06: "undefined",
              0x07: "objectId", 0x08: "bool", 0x09: "date", 0x0A: "null", 0x0B: "regex", 0x0C: "dbPointer",
              0x0D: "javascript", 0x0E: "symbol", 0x0F: "javascriptWithScope", 0x10: "int", 0x11: "timestamp",
              0x12: "long", 0x13: "decimal", 0xFF: "minKey", 0x7F: "maxKey"}


def _cstring(b, p):
    z = b.index(b"\0", p)
    return b[p:z].decode("utf-8", "replace"), z + 1


def _string(b, p, end):
    n = struct.unpack_from("<i", b, p)[0]
    if n < 1 or p + 4 + n > end or b[p + 3 + n] != 0:
        raise BSONError(f"문자열 길이 오류 @{p}")
    return b[p + 4:p + 3 + n].decode("utf-8", "replace"), p + 4 + n


def _value(b, t, p, end, depth):
    if t == 0x01:
        return struct.unpack_from("<d", b, p)[0], p + 8
    if t in (0x02, 0x0D):
        s, q = _string(b, p, end)
        return (s if t == 0x02 else Other("javascript", s)), q
    if t == 0x0E:
        s, q = _string(b, p, end)
        return Other("symbol", s), q
    if t in (0x03, 0x04):
        n = struct.unpack_from("<i", b, p)[0]
        d = _doc(b, p, depth + 1)
        if t == 0x04:
            d = list(d.values())
        return d, p + n
    if t == 0x05:
        n = struct.unpack_from("<i", b, p)[0]
        if n < 0 or p + 5 + n > end:
            raise BSONError(f"바이너리 길이 오류 @{p}")
        sub = b[p + 4]
        # 옛 바이너리(서브타입 2)는 안쪽에 길이가 한 번 더 있지만, 증거 원본을 바꾸지 않도록 그대로 둔다
        return Binary(b[p + 5:p + 5 + n], sub), p + 5 + n
    if t == 0x07:
        return ObjectId(b[p:p + 12]), p + 12
    if t == 0x08:
        return bool(b[p]), p + 1
    if t == 0x09:
        return Date(struct.unpack_from("<q", b, p)[0]), p + 8
    if t in (0x06, 0x0A):
        return None, p
    if t == 0xFF:
        return Other("minKey", 1), p
    if t == 0x7F:
        return Other("maxKey", 1), p
    if t == 0x0B:
        pat, q = _cstring(b, p)
        opt, q = _cstring(b, q)
        return Other("regex", (pat, opt)), q
    if t == 0x0C:
        s, q = _string(b, p, end)
        return Other("dbPointer", (s, b[q:q + 12].hex())), q + 12
    if t == 0x0F:
        n = struct.unpack_from("<i", b, p)[0]
        code, q = _string(b, p + 4, p + n)
        return Other("javascriptWithScope", (code, _doc(b, q, depth + 1))), p + n
    if t == 0x10:
        return struct.unpack_from("<i", b, p)[0], p + 4
    if t == 0x11:
        inc, sec = struct.unpack_from("<II", b, p)
        return Timestamp(sec, inc), p + 8
    if t == 0x12:
        return struct.unpack_from("<q", b, p)[0], p + 8
    if t == 0x13:
        return Other("decimal", b[p:p + 16].hex()), p + 16
    raise BSONError(f"알 수 없는 BSON 타입 0x{t:02x} @{p}")


def _doc(b, p, depth=0):
    if depth > 100:
        raise BSONError("중첩이 너무 깊음")
    if p + 5 > len(b):
        raise BSONError("문서가 버퍼를 넘음")
    n = struct.unpack_from("<i", b, p)[0]
    end = p + n
    if n < 5 or end > len(b) or b[end - 1] != 0:
        raise BSONError(f"문서 길이/종료 바이트 오류 @{p} (len {n})")
    out = {}
    q = p + 4
    while q < end - 1:
        t = b[q]
        k, q = _cstring(b, q + 1)
        v, q = _value(b, t, q, end, depth)
        if q > end - 1:
            raise BSONError(f"요소가 문서 끝을 넘음 ({k})")
        out[k] = v
    if q != end - 1:
        raise BSONError("문서 끝 불일치")
    return out


def decode(b: bytes, p: int = 0) -> dict:
    """손상된 입력의 모든 실패(잘린 값, NUL 없는 이름 등)를 BSONError 하나로 돌려준다."""
    try:
        return _doc(b, p)
    except BSONError:
        raise
    except (ValueError, IndexError, struct.error, TypeError, RecursionError) as e:
        raise BSONError(f"BSON 손상: {type(e).__name__}: {e}") from None


def doc_length(b: bytes, p: int = 0) -> int:
    return struct.unpack_from("<i", b, p)[0]


def elements(b: bytes) -> list[dict]:
    try:
        return _elements(b)
    except BSONError:
        raise
    except (ValueError, IndexError, struct.error, TypeError) as e:
        raise BSONError(f"BSON 손상: {type(e).__name__}: {e}") from None


def _elements(b: bytes) -> list[dict]:
    """최상위 요소의 위치: [{name, type, start, header_len, len}] (start 는 요소 머리 = 타입 바이트)."""
    n = struct.unpack_from("<i", b, 0)[0]
    out, q = [], 4
    while q < n - 1:
        t = b[q]
        k, vq = _cstring(b, q + 1)
        _, nq = _value(b, t, vq, n, 0)
        out.append({"name": k, "type": TYPE_NAMES.get(t, f"0x{t:02x}"), "start": q, "header_len": vq - q, "len": nq - q})
        q = nq
    return out


# ------------------------------------------------------------------ JSON 변환

def to_json(v, bin_limit: int | None = 64):
    """확장 JSON(relaxed). bin_limit 바이트를 넘는 바이너리는 앞부분만 base64 로 싣고 길이를 적는다."""
    if v is None or isinstance(v, (bool, str)):
        return v
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return v if v == v and v not in (float("inf"), float("-inf")) else {"$numberDouble": str(v)}
    if isinstance(v, dict):
        return {k: to_json(x, bin_limit) for k, x in v.items()}
    if isinstance(v, list):
        return [to_json(x, bin_limit) for x in v]
    if isinstance(v, ObjectId):
        return {"$oid": str(v)}
    if isinstance(v, Date):
        return {"$date": v.iso()}
    if isinstance(v, Timestamp):
        return {"$timestamp": {"t": v.t, "i": v.i}}
    if isinstance(v, Binary):
        if v.subtype in (0x03, 0x04) and len(v.data) == 16:
            return {"$uuid": str(_uuid.UUID(bytes=v.data))}
        data = v.data if bin_limit is None else v.data[:bin_limit]
        out = {"$binary": {"base64": base64.b64encode(data).decode(), "subType": f"{v.subtype:02x}"}}
        if bin_limit is not None and len(v.data) > bin_limit:
            out["$binary"]["truncated"] = True
            out["$binary"]["length"] = len(v.data)
        return out
    if isinstance(v, Other):
        if v.kind == "regex":
            return {"$regularExpression": {"pattern": v.value[0], "options": v.value[1]}}
        if v.kind == "decimal":
            return {"$numberDecimal": decimal128(bytes.fromhex(v.value))}
        if v.kind in ("minKey", "maxKey"):
            return {"$" + v.kind: 1}
        if v.kind == "javascriptWithScope":
            return {"$code": v.value[0], "$scope": to_json(v.value[1], bin_limit)}
        return {"$" + v.kind: v.value if not isinstance(v.value, tuple) else list(v.value)}
    return str(v)


def canonical(v) -> str:
    """같은 문서인지 비교용 문자열 (바이너리 전체 포함, 키 순서 유지)."""
    return json.dumps(to_json(v, None), ensure_ascii=False, separators=(",", ":"))


def decimal128(b: bytes) -> str:
    lo, hi = struct.unpack("<QQ", b)
    sign = "-" if hi >> 63 else ""
    if (hi >> 58) & 0x1F == 0x1F:
        return "NaN"
    if (hi >> 58) & 0x1F == 0x1E:
        return sign + "Infinity"
    if (hi >> 61) & 3 == 3:
        exp = (hi >> 47) & 0x3FFF
        coef = 0
    else:
        exp = (hi >> 49) & 0x3FFF
        coef = ((hi & ((1 << 49) - 1)) << 64) | lo
    exp -= 6176
    s = str(coef)
    if exp == 0:
        return sign + s
    if exp > 0:
        return sign + s + "E+" + str(exp)
    if len(s) > -exp:
        return sign + s[:exp] + "." + s[exp:]
    return sign + "0." + "0" * (-exp - len(s)) + s


def short_text(v, limit: int = 300) -> str:
    """표 셀용 짧은 표시 문자열."""
    if isinstance(v, str):
        s = v
    elif isinstance(v, Binary):
        s = f"Binary({v.subtype:02x}, {len(v.data)} B)"
    elif isinstance(v, ObjectId):
        s = f"ObjectId({v})"
    elif isinstance(v, Date):
        s = v.iso()
    else:
        s = json.dumps(to_json(v, 16), ensure_ascii=False, separators=(",", ":"))
    return s if len(s) <= limit else s[:limit] + "…"

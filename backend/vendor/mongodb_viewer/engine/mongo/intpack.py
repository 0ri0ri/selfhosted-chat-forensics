"""WiredTiger 가변 길이 정수 패킹 (src/include/intpack_inline.h).

첫 바이트의 상위 비트가 형식을 정한다 [문서: intpack_inline.h]
  0x00-0x0F  (미사용)
  0x10-0x1F  NEG_MULTI   : 하위 4비트 = 8 - 바이트 수, 이어지는 빅엔디언 바이트를 부호 확장
  0x20-0x3F  NEG_2BYTE   : 13비트 값 - 8256
  0x40-0x7F  NEG_1BYTE   : 6비트 값 - 64
  0x80-0xBF  POS_1BYTE   : 6비트 값
  0xC0-0xDF  POS_2BYTE   : 13비트 값 + 64
  0xE0-0xEF  POS_MULTI   : 하위 4비트 = 바이트 수, 빅엔디언 값 + 8256
부호 없는 정수(vunpack_uint)는 양수 형식만 쓴다. 0x2040 = 8256 이다.
"""

from __future__ import annotations


class PackError(ValueError):
    pass


def unpack_uint(b: bytes, p: int) -> tuple[int, int]:
    """(값, 다음 위치)."""
    try:
        x = b[p]
    except IndexError:
        raise PackError(f"패킹 정수가 버퍼를 넘음 @{p}")
    if x & 0xF0 == 0xE0:
        n = x & 0x0F
        if p + 1 + n > len(b):
            raise PackError(f"POS_MULTI 가 버퍼를 넘음 @{p}")
        return int.from_bytes(b[p + 1:p + 1 + n], "big") + 0x2040, p + 1 + n
    if x & 0xE0 == 0xC0:
        if p + 2 > len(b):
            raise PackError(f"POS_2BYTE 가 버퍼를 넘음 @{p}")
        return (((x & 0x1F) << 8) | b[p + 1]) + 0x40, p + 2
    if x & 0xC0 == 0x80:
        return x & 0x3F, p + 1
    raise PackError(f"부호 없는 패킹 정수가 아님 0x{x:02x} @{p}")


def unpack_int(b: bytes, p: int) -> tuple[int, int]:
    x = b[p]
    if x & 0xF0 == 0x10:
        n = 8 - (x & 0x0F)
        raw = b[p + 1:p + 1 + n]
        if len(raw) != n:
            raise PackError(f"NEG_MULTI 가 버퍼를 넘음 @{p}")
        v = int.from_bytes(raw, "big") - (1 << (8 * n)) if n else -1
        return v, p + 1 + n
    if x & 0xE0 == 0x20:
        return (((x & 0x1F) << 8) | b[p + 1]) - 0x2040, p + 2
    if x & 0xC0 == 0x40:
        return (x & 0x3F) - 0x40, p + 1
    return unpack_uint(b, p)


def unpack_format(fmt: str, b: bytes) -> list:
    """WiredTiger 패킹 형식 문자열 일부 (q Q I i r u S s) 를 푼다. 'u' 는 마지막이면 나머지 전부,
    중간이면 길이(uint) 접두. 'S' 는 NUL 종료 문자열."""
    out, p = [], 0
    for i, c in enumerate(fmt):
        last = i == len(fmt) - 1
        if c in "qi":
            v, p = unpack_int(b, p)
        elif c in "QIr":
            v, p = unpack_uint(b, p)
        elif c == "u":
            if last:
                v, p = bytes(b[p:]), len(b)
            else:
                n, p = unpack_uint(b, p)
                v, p = bytes(b[p:p + n]), p + n
        elif c in "Ss":
            z = b.find(b"\0", p)
            z = len(b) if z < 0 else z
            v, p = b[p:z].decode("utf-8", "replace"), z + 1
        else:
            raise PackError(f"지원하지 않는 형식 문자 {c!r}")
        out.append(v)
    return out

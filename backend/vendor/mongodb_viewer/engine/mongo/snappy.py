"""Snappy raw 형식 해제 (google/snappy format_description.txt). 압축은 하지 않는다.

스트림 = 원래 길이(varint) + 요소들. 태그 하위 2비트:
  00 리터럴  : 길이-1 이 태그 상위 6비트, 60~63 이면 뒤 1~4바이트(LE)에 길이-1
  01 복사    : 길이 4~11 (태그 비트 2~4), 오프셋 11비트 (태그 상위 3비트 + 1바이트)
  10 복사    : 길이 1~64, 오프셋 2바이트 LE
  11 복사    : 길이 1~64, 오프셋 4바이트 LE
복사는 겹칠 수 있다 (오프셋 < 길이).
"""

from __future__ import annotations


class SnappyError(ValueError):
    pass


def decompress(src: bytes) -> bytes:
    try:
        return _decompress(src)
    except SnappyError:
        raise
    except (IndexError, ValueError) as e:      # 잘린 스트림
        raise SnappyError(f"스트림 손상: {type(e).__name__}: {e}") from None


def _need(src, p, k):
    if p + k > len(src):
        raise SnappyError("태그 뒤 바이트가 모자람 (잘린 스트림)")


def _decompress(src: bytes) -> bytes:
    p, shift, n = 0, 0, 0
    while True:
        if p >= len(src) or shift > 32:
            raise SnappyError("길이 헤더 손상")
        c = src[p]
        p += 1
        n |= (c & 0x7F) << shift
        if c < 0x80:
            break
        shift += 7
    out = bytearray()
    end = len(src)
    while p < end:
        tag = src[p]
        p += 1
        t = tag & 3
        if t == 0:
            ln = tag >> 2
            if ln >= 60:
                k = ln - 59
                _need(src, p, k)
                ln = int.from_bytes(src[p:p + k], "little")
                p += k
            ln += 1
            if p + ln > end:
                raise SnappyError("리터럴이 입력을 넘음")
            out += src[p:p + ln]
            p += ln
            continue
        if t == 1:
            _need(src, p, 1)
            ln = 4 + ((tag >> 2) & 7)
            off = ((tag >> 5) << 8) | src[p]
            p += 1
        elif t == 2:
            _need(src, p, 2)
            ln = (tag >> 2) + 1
            off = int.from_bytes(src[p:p + 2], "little")
            p += 2
        else:
            _need(src, p, 4)
            ln = (tag >> 2) + 1
            off = int.from_bytes(src[p:p + 4], "little")
            p += 4
        if off == 0 or off > len(out):
            raise SnappyError("복사 오프셋 오류")
        s = len(out) - off
        if off >= ln:
            out += out[s:s + ln]
        else:
            for i in range(ln):
                out.append(out[s + i])
    if len(out) != n:
        raise SnappyError(f"해제 길이 불일치 {len(out)} != {n}")
    return bytes(out)

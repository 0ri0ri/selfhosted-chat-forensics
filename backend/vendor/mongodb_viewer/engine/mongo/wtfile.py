"""WiredTiger 파일(.wt) 리더 - 블록 매니저와 행 저장소(row-store) B-tree.

근거는 WiredTiger 소스 [문서]: src/include/block.h(디스크립터, 블록 헤더, 체크포인트 쿠키),
btmem.h(페이지 헤더, 페이지 타입, 플래그), cell.h / cell_inline.h(셀), intpack_inline.h(정수),
ext/compressors/snappy/snappy_compress.c(압축 래퍼). 샘플(MongoDB 8.2, WiredTiger 12.0.0)로 확인한 것은 [검증].

블록 = 페이지 헤더 28B + 블록 헤더 12B + 데이터. 압축 블록은 앞 64B(WT_BLOCK_COMPRESS_SKIP)를 그대로 두고
나머지를 압축한다. snappy 는 압축 데이터 앞에 8B LE 길이를 둔다 [검증].
주소 쿠키 = 패킹된 (offset, size, checksum), 실제 위치 = (offset+1) * allocation_size [검증].
"""

from __future__ import annotations

import struct
import zlib

from . import snappy
from .intpack import PackError, unpack_uint, unpack_int

BLOCK_MAGIC = 120897            # 0x1D841
PAGE_HDR = 28
BLK_HDR = 12
COMPRESS_SKIP = 64
PAGE_TYPES = {1: "BLOCK_MANAGER", 2: "COL_FIX", 3: "COL_INT", 4: "COL_VAR", 5: "OVFL", 6: "ROW_INT", 7: "ROW_LEAF"}
PAGE_FLAGS = {0x01: "COMPRESSED", 0x02: "EMPTY_V_ALL", 0x04: "EMPTY_V_NONE", 0x08: "ENCRYPTED", 0x10: "UNUSED", 0x20: "FT_UPDATE"}
CELL_TYPES = {0x00: "ADDR_DEL", 0x10: "ADDR_INT", 0x20: "ADDR_LEAF", 0x30: "ADDR_LEAF_NO", 0x40: "DEL", 0x50: "KEY",
              0x60: "KEY_OVFL", 0x70: "KEY_PFX", 0x80: "VALUE", 0x90: "VALUE_COPY", 0xA0: "VALUE_OVFL",
              0xB0: "VALUE_OVFL_RM", 0xC0: "KEY_OVFL_RM", 0xD0: "ADDR_DEL_VISIBLE_ALL"}
TS_MAX = (1 << 64) - 1
TXN_MAX = (1 << 64) - 11        # WT_TXN_MAX 근사 (stop 없음 표시용, 비교에는 쓰지 않는다)


class WTError(ValueError):
    pass


# ------------------------------------------------------------------ CRC-32C (Castagnoli)

def _crc_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t


_CRC = _crc_table()


def crc32c(data: bytes) -> int:
    c = 0xFFFFFFFF
    t = _CRC
    for x in data:
        c = t[(c ^ x) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFF


# ------------------------------------------------------------------ 블록

def page_header(raw: bytes) -> dict:
    if len(raw) < PAGE_HDR + BLK_HDR:
        raise WTError("블록이 헤더보다 짧음")
    recno, write_gen, mem_size, entries, ptype, flags, reserved, version = struct.unpack_from("<QQIIBBBB", raw, 0)
    disk_size, cksum, bflags = struct.unpack_from("<IIB", raw, PAGE_HDR)
    return {"recno": recno, "write_gen": write_gen, "mem_size": mem_size, "entries": entries, "type": ptype,
            "type_name": PAGE_TYPES.get(ptype, "?"), "flags": flags,
            "flag_names": [n for b, n in PAGE_FLAGS.items() if flags & b], "version": version,
            "disk_size": disk_size, "checksum": cksum, "block_flags": bflags}


class WTFile:
    """.wt 파일 하나. data 는 파일 전체 바이트 (읽기 전용)."""

    def __init__(self, name: str, data: bytes, config: str = ""):
        self.name = name
        self.data = data
        self.config = config
        self.alloc = parse_size(cfg_value(config, "allocation_size") or "4KB")
        comp = cfg_value(config, "block_compressor") or ""
        self.compressor = comp or None
        if len(data) < 16:
            raise WTError(f"{name}: 파일이 너무 짧음")
        magic, major, minor, cks = struct.unpack_from("<IHHI", data, 0)
        if magic != BLOCK_MAGIC:
            raise WTError(f"{name}: WiredTiger 블록 매직이 아님 (0x{magic:x})")
        self.desc = {"magic": magic, "major": major, "minor": minor, "checksum": cks}
        self._img_cache: dict[int, tuple] = {}

    # -- 블록 읽기
    def block(self, off: int, size: int | None = None, verify: bool = False) -> tuple[dict, bytes]:
        hit = self._img_cache.get(off)
        if hit is not None:
            if size is not None and size != hit[0]["disk_size"]:
                raise WTError(f"주소 쿠키 크기({size})와 블록 disk_size({hit[0]['disk_size']}) 불일치 @{off}")
            return hit
        if off < self.alloc or off + PAGE_HDR + BLK_HDR > len(self.data):
            raise WTError(f"블록 위치가 파일 밖 @{off}")
        h = page_header(self.data[off:off + PAGE_HDR + BLK_HDR])
        ds = h["disk_size"]
        if ds < self.alloc or ds % self.alloc or off + ds > len(self.data) or h["type"] not in PAGE_TYPES:
            raise WTError(f"블록 헤더 이상 @{off} (type {h['type']}, disk_size {ds})")
        if size is not None and size != ds:
            raise WTError(f"주소 쿠키 크기({size})와 블록 disk_size({ds}) 불일치 @{off}")
        raw = self.data[off:off + ds]
        if verify:
            h["checksum_ok"] = self.checksum_ok(raw, h)
        if h["flags"] & 0x08:
            raise WTError(f"암호화된 블록 @{off} - 지원하지 않음")
        if h["flags"] & 0x01:
            body = raw[COMPRESS_SKIP:]
            if self.compressor == "snappy":
                clen = struct.unpack_from("<Q", body, 0)[0]
                if clen > len(body) - 8:
                    raise WTError(f"snappy 길이 이상 @{off}")
                plain = snappy.decompress(body[8:8 + clen])
            elif self.compressor == "zlib":
                try:
                    plain = zlib.decompress(body)
                except zlib.error:
                    plain = zlib.decompressobj(-15).decompress(body)
            elif self.compressor in ("zstd", "lz4"):
                raise WTError(f"{self.compressor} 압축 블록은 지원하지 않습니다 (표준 라이브러리에 없음)")
            else:
                raise WTError(f"압축 블록인데 block_compressor 설정이 없음 @{off}")
            img = raw[:COMPRESS_SKIP] + plain
        else:
            img = raw
        if h["mem_size"] > len(img):
            raise WTError(f"메모리 크기({h['mem_size']})가 이미지보다 큼 @{off}")
        img = img[:h["mem_size"]]
        res = (h, img)
        if len(self._img_cache) > 4096:
            self._img_cache.clear()
        self._img_cache[off] = res
        return res

    @staticmethod
    def checksum_ok(raw: bytes, h: dict) -> bool:
        """블록 헤더의 checksum 필드를 0 으로 두고 CRC-32C. DATA_CKSUM 이면 블록 전체, 아니면 앞 64B."""
        buf = bytearray(raw if h["block_flags"] & 1 else raw[:COMPRESS_SKIP])
        buf[PAGE_HDR + 4:PAGE_HDR + 8] = b"\0\0\0\0"
        return crc32c(bytes(buf)) == h["checksum"]

    # -- 주소
    def addr(self, cookie: bytes):
        o, p = unpack_uint(cookie, 0)
        s, p = unpack_uint(cookie, p)
        c, p = unpack_uint(cookie, p)
        if s == 0:
            return None
        return (o + 1) * self.alloc, s * self.alloc, c

    def checkpoint(self, addr_hex: str) -> dict:
        b = bytes.fromhex(addr_hex)
        if not b:
            return {"root": None}
        p = 1  # 쿠키 버전 바이트
        vals = []
        for _ in range(4):
            o, p = unpack_uint(b, p)
            s, p = unpack_uint(b, p)
            c, p = unpack_uint(b, p)
            vals.append(None if s == 0 else ((o + 1) * self.alloc, s * self.alloc, c))
        fsize, p = unpack_uint(b, p)
        csize, p = unpack_uint(b, p)
        return {"version": b[0], "root": vals[0], "alloc": vals[1], "avail": vals[2], "discard": vals[3],
                "file_size": fsize, "ckpt_size": csize}

    # -- 셀
    def cells(self, img: bytes) -> list[dict]:
        try:
            return self._cells(img)
        except WTError:
            raise
        except (PackError, IndexError) as e:
            raise WTError(f"셀 해석 실패: {type(e).__name__}: {e}") from None

    def _cells(self, img: bytes) -> list[dict]:
        out = []
        p = PAGE_HDR + BLK_HDR
        end = len(img)
        while p < end:
            d = img[p]
            c = {"off": p, "desc": d}
            st = d & 3
            if st:
                if st == 1:
                    c["type"] = "KEY"
                    ln = d >> 2
                    p += 1
                elif st == 2:
                    c["type"] = "KEY_PFX"
                    c["prefix"] = img[p + 1]
                    ln = d >> 2
                    p += 2
                else:
                    c["type"] = "VALUE"
                    ln = d >> 2
                    p += 1
                if p + ln > end:
                    raise WTError(f"짧은 셀 데이터가 페이지를 넘음 @{c['off']}")
                c["data_off"] = p
                c["data"] = img[p:p + ln]
                p += ln
                out.append(c)
                continue
            name = CELL_TYPES.get(d & 0xF0)
            if name is None:
                raise WTError(f"알 수 없는 셀 0x{d:02x} @{p}")
            c["type"] = name
            p += 1
            if d & 0x08:                      # WT_CELL_SECOND_DESC: 시간 창
                fl = img[p]
                p += 1
                tw = {}
                if fl & 0x08:
                    tw["start_ts"], p = unpack_uint(img, p)
                if fl & 0x20:
                    tw["start_txn"], p = unpack_uint(img, p)
                if fl & 0x02:
                    v, p = unpack_uint(img, p)
                    tw["durable_start_ts"] = v + tw.get("start_ts", 0)
                if fl & 0x10:
                    v, p = unpack_uint(img, p)
                    tw["stop_ts"] = v + tw.get("start_ts", 0)
                if fl & 0x40:
                    v, p = unpack_uint(img, p)
                    tw["stop_txn"] = v + tw.get("start_txn", 0)
                if fl & 0x04:
                    v, p = unpack_uint(img, p)
                    tw["durable_stop_ts"] = v + tw.get("stop_ts", 0)
                if fl & 0x01:
                    tw["prepare"] = True
                c["tw"] = tw
            if name == "KEY_PFX":
                c["prefix"] = img[p]
                p += 1
            if d & 0x04:                      # WT_CELL_64V: RLE 등 연관 값
                c["rle"], p = unpack_uint(img, p)
            if name in ("DEL",):
                c["data"] = b""
                out.append(c)
                continue
            if name == "VALUE_COPY":
                c["copy"], p = unpack_uint(img, p)
                out.append(c)
                continue
            ln, p = unpack_uint(img, p)
            if name in ("KEY", "KEY_PFX", "VALUE") and not d & 0x04:
                ln += 64                      # WT_CELL_SIZE_ADJUST - 64V 셀은 보정하지 않는다 [검증]
            if p + ln > end:
                raise WTError(f"셀 데이터가 페이지를 넘음 @{c['off']}")
            c["data_off"] = p
            c["data"] = img[p:p + ln]
            p += ln
            out.append(c)
        return out

    def overflow(self, cookie: bytes) -> bytes:
        a = self.addr(cookie)
        if a is None:
            raise WTError("빈 오버플로 주소")
        h, img = self.block(a[0], a[1])
        if h["type"] != 5:
            raise WTError(f"오버플로 페이지가 아님 @{a[0]}")
        return img[PAGE_HDR + BLK_HDR:PAGE_HDR + BLK_HDR + h["entries"]]   # OVFL 은 entries 자리가 datalen

    def leaf_rows(self, img: bytes) -> list[dict]:
        """ROW_LEAF 이미지 → [{key, value, cell, problem}] (value None = 값 없음/삭제/해석 실패, problem 에 이유)."""
        rows = []
        cells = self.cells(img)
        by_off = {c["off"]: c for c in cells}
        last_key = b""
        cur = None
        for c in cells:
            t = c["type"]
            if t in ("KEY", "KEY_PFX", "KEY_OVFL", "KEY_OVFL_RM"):
                if cur is not None:
                    rows.append(cur)
                # 키를 못 읽으면 last_key 를 None 으로 두어, 그 키에 기대는 다음 접두 압축 키도 오류로 표시한다
                if t == "KEY_OVFL":
                    try:
                        k = self.overflow(c["data"])
                    except (WTError, PackError) as e:
                        cur = {"key": None, "value": None, "cell": None, "key_cell": c, "problem": f"오버플로 키 해석 실패: {e}"}
                        last_key = None
                        continue
                elif t == "KEY_OVFL_RM":
                    cur = {"key": None, "value": None, "cell": None, "key_cell": c, "problem": "제거된 오버플로 키"}
                    last_key = None
                    continue
                else:
                    pre = c.get("prefix", 0)
                    if pre and last_key is None:
                        cur = {"key": None, "value": None, "cell": None, "key_cell": c, "problem": "앞 키를 읽지 못해 접두 압축 키를 복원할 수 없음"}
                        continue
                    if pre > len(last_key or b""):
                        cur = {"key": None, "value": None, "cell": None, "key_cell": c, "problem": "키 접두 길이 오류"}
                        last_key = None
                        continue
                    k = (last_key or b"")[:pre] + c["data"]
                last_key = k
                cur = {"key": k, "value": None, "cell": None, "key_cell": c, "problem": "값 셀 없음"}
            elif t in ("VALUE", "VALUE_OVFL", "VALUE_COPY", "DEL", "VALUE_OVFL_RM"):
                if cur is None:
                    cur = {"key": None, "value": None, "cell": None, "key_cell": None, "problem": "키 없는 값"}
                cc = c
                prob = None
                if t == "VALUE_COPY":
                    cc = by_off.get(c["off"] - c["copy"])
                    if cc is None:
                        prob = "VALUE_COPY 대상 셀을 찾지 못함"
                v = None
                if prob is None:
                    if cc["type"] == "VALUE_OVFL":
                        try:
                            v = self.overflow(cc["data"])
                        except (WTError, PackError) as e:
                            prob = f"오버플로 값 해석 실패: {e}"
                    elif cc["type"] == "VALUE_OVFL_RM":
                        prob = "제거된 오버플로 값"
                    elif cc["type"] == "DEL":
                        prob = "삭제 셀"
                    else:
                        v = cc.get("data", b"")
                cur.update({"value": v, "cell": c, "value_cell": cc, "problem": prob})
                rows.append(cur)
                cur = None
        if cur is not None:
            rows.append(cur)
        return rows

    # -- 순회
    def walk(self, root) -> list[tuple[int, dict, bytes]]:
        """체크포인트 루트에서 닿는 페이지 (오프셋, 헤더, 이미지). 순환 방지."""
        out, seen, stack = [], set(), [root]
        while stack:
            off, size, _ = stack.pop()
            if off in seen:
                continue
            seen.add(off)
            h, img = self.block(off, size)
            out.append((off, h, img))
            if h["type"] == 6:
                kids = []
                for c in self.cells(img):
                    if c["type"] in ("ADDR_INT", "ADDR_LEAF", "ADDR_LEAF_NO"):
                        a = self.addr(c["data"])
                        if a:
                            kids.append(a)
                stack.extend(reversed(kids))
        return out

    def scan(self, verify: bool = True) -> tuple[list[tuple[int, dict, bytes]], list[dict]]:
        """파일 전체를 할당 단위로 훑어 헤더가 맞는 블록. (블록 목록, 문제 목록).
        체크섬이 맞지 않거나 해제에 실패한 블록은 문제 목록에 남긴다 (조용히 버리지 않는다)."""
        blocks, problems = [], []
        off = self.alloc
        n = len(self.data)
        while off + PAGE_HDR + BLK_HDR <= n:
            try:
                h = page_header(self.data[off:off + PAGE_HDR + BLK_HDR])
            except WTError:
                off += self.alloc
                continue
            ds = h["disk_size"]
            plausible = (h["type"] in PAGE_TYPES and ds >= self.alloc and ds % self.alloc == 0 and off + ds <= n
                         and h["version"] in (0, 1, 2) and h["block_flags"] in (0, 1))
            if not plausible:
                off += self.alloc
                continue
            raw = self.data[off:off + ds]
            if verify and not self.checksum_ok(raw, h):
                problems.append({"offset": off, "problem": "체크섬 불일치 (덮어쓴 블록이거나 블록이 아님)"})
                off += self.alloc
                continue
            try:
                h2, img = self.block(off)
            except Exception as e:                       # 덮어쓴 블록은 어떤 식으로든 깨질 수 있다 - 기록하고 넘어간다
                problems.append({"offset": off, "problem": f"해제 실패: {type(e).__name__}: {e}"})
                off += self.alloc
                continue
            blocks.append((off, h2, img))
            off += ds
        return blocks, problems


# ------------------------------------------------------------------ 설정 문자열

def cfg_value(cfg: str, key: str) -> str | None:
    """WiredTiger 설정 문자열에서 최상위 key=값 (괄호 안 중첩은 건너뛴다)."""
    depth, i, n = 0, 0, len(cfg)
    while i < n:
        ch = cfg[i]
        if ch == '"':                                   # 따옴표 안의 괄호, 쉼표는 구조가 아니다
            j = cfg.find('"', i + 1)
            i = n if j < 0 else j + 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif depth == 0 and (i == 0 or cfg[i - 1] == ",") and cfg.startswith(key + "=", i):
            j = i + len(key) + 1
            if j < n and cfg[j] == "(":
                d, k = 0, j
                while k < n:
                    if cfg[k] == "(":
                        d += 1
                    elif cfg[k] == ")":
                        d -= 1
                        if d == 0:
                            return cfg[j:k + 1]
                    k += 1
                return cfg[j:]
            k = cfg.find(",", j)
            return cfg[j:] if k < 0 else cfg[j:k]
        i += 1
    return None


def parse_size(s: str) -> int:
    s = s.strip().upper()
    mult = {"KB": 1 << 10, "MB": 1 << 20, "GB": 1 << 30, "B": 1}
    for suf, m in mult.items():
        if s.endswith(suf):
            return int(s[:-len(suf)]) * m
    return int(s)


def checkpoints(cfg: str) -> list[dict]:
    """checkpoint=(이름=(addr="..",order=N,time=T,size=S,...),...) → order 오름차순 목록."""
    import re
    out = []
    for m in re.finditer(r'([\w.]+)=\(addr="([0-9a-f]*)",order=(\d+),time=(\d+),size=(\d+)', cfg):
        out.append({"name": m.group(1), "addr": m.group(2), "order": int(m.group(3)), "time": int(m.group(4)),
                    "size": int(m.group(5))})
    return sorted(out, key=lambda c: c["order"])


def record_id(key: bytes | None) -> int | None:
    """패킹된 int64 RecordId. 비었거나 해석하지 못하면 None (클러스터드 컬렉션의 문자열 키 등)."""
    if not key:
        return None
    try:
        return unpack_int(key, 0)[0]
    except (PackError, IndexError):
        return None

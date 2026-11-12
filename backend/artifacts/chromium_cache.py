from __future__ import annotations

import gzip
import zlib
from pathlib import Path

import backend.vendor
from ccl_chromium_reader import ccl_chromium_cache

from .. import handles

SAFE_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "image/x-icon",
                    "image/vnd.microsoft.icon", "image/avif"}
TEXT_HINTS = ("text/", "json", "javascript", "ecmascript", "xml", "css", "svg", "x-www-form-urlencoded")
TEXT_LIMIT = 1_000_000


class _Opened:
    def __init__(self, d: Path):
        self.cache = ccl_chromium_cache.ChromiumBlockFileCache(d)
        try:
            self.by_url: dict[str, list[str]] = {}
            for k in self.cache.keys():
                self.by_url.setdefault(url_of(k), []).append(k)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        for _, f in self.cache._block_files.values():
            try:
                f.close()
            except OSError:
                pass


def _open(extracted: Path) -> _Opened | None:
    d = find_cache_dir(extracted)
    return _Opened(d) if d is not None else None


REGISTRY = handles.Registry("chromium_cache", 2, _open, lambda o: o.close())


def url_of(key: str) -> str:
    url = key.split(" ")[-1]
    return url[url.find("http"):] if "http" in url else url


def find_cache_dir(extracted: Path) -> Path | None:
    found = [i.parent for i in extracted.rglob("index")
             if (i.parent / "data_0").is_file() and (i.parent / "data_1").is_file()]
    for d in sorted(found, key=lambda p: ("Partitions" not in p.parts, len(p.parts))):
        if d.name == "Cache_Data" or (d.name == "Cache" and d.parent.name != "Cache"):
            return d
    return None


def decode_body(data: bytes, encoding: str) -> tuple[bytes, str]:
    enc = (encoding or "").lower()
    try:
        if data[:2] == b"\x1f\x8b" or "gzip" in enc:
            return gzip.decompress(data), "gzip 해제"
        if "deflate" in enc:
            try:
                return zlib.decompress(data), "deflate 해제"
            except zlib.error:
                return zlib.decompress(data, -zlib.MAX_WBITS), "deflate(raw) 해제"
        if "br" in [x.strip() for x in enc.split(",")]:
            try:
                import brotli
            except ImportError:
                return data, "brotli 압축 - brotli 패키지가 없어 원본 바이트를 보여 줍니다"
            return brotli.decompress(data), "brotli 해제"
    except Exception as e:
        return data, f"압축 해제 실패 ({type(e).__name__}) - 원본 바이트를 보여 줍니다"
    return data, ""


def lookup(extracted: Path, url: str, key: str | None = None) -> dict:
    with REGISTRY.use(extracted) as h:
        if h.obj is None:
            raise FileNotFoundError("캐시 폴더(index, data_0~3)를 찾지 못했습니다")
        keys = h.obj.by_url.get(url) or []
        if key is not None:
            keys = [k for k in keys if k == key]
        if not keys:
            raise KeyError("해당 URL 의 캐시 엔트리가 없습니다")
        key = keys[0]
        with h.lock:
            h.check()
            cache = h.obj.cache
            es = cache._keys[key]
            md = (cache.get_metadata(key) or [None])[0]
            raw = (cache.get_cachefile(key) or [None])[0]
            loc = (cache.get_location_for_cachefile(key) or [None])[0]
    headers = list(md.http_header_attributes) if md else []
    status_line = next(iter(md.http_header_declarations), "") if md else ""
    ctype = ", ".join(md.get_attribute("content-type")) if md else ""
    encoding = ", ".join(md.get_attribute("content-encoding")) if md else ""
    body, note = decode_body(raw, encoding) if raw is not None else (None, "본문 스트림 없음")
    return {
        "key": key, "url": url, "created": es.creation_time,
        "request_time": md.request_time if md else None, "response_time": md.response_time if md else None,
        "status": status_line, "headers": headers, "ctype": ctype, "encoding": encoding,
        "raw_size": len(raw) if raw is not None else None, "body": body, "note": note,
        "location": f"{loc.file_name} @ {loc.offset}" if loc else "",
    }


def classify(ctype: str, body: bytes | None) -> str:
    if not body:
        return "empty"
    base = (ctype or "").split(";")[0].strip().lower()
    if base in SAFE_IMAGE_TYPES:
        return "image"
    if any(h in base for h in TEXT_HINTS):
        return "text"
    sample = body[:4096]
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return "binary"
    ctrl = sum(1 for ch in text if ord(ch) < 32 and ch not in "\r\n\t")
    return "text" if ctrl <= len(text) * 0.02 else "binary"

from __future__ import annotations

import base64
import json

try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    from Crypto.Util.Padding import unpad
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

PREFIXED_B64_LEN = 344


class E2EError(ValueError):
    pass


def b64(s: str) -> bytes:
    s = s.strip()
    return base64.b64decode(s + "=" * (-len(s) % 4))


def b64url(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _int(s: str) -> int:
    return int.from_bytes(b64url(s), "big")


def private_key(jwk: dict | str):
    if not AVAILABLE:
        raise E2EError("pycryptodome 이 설치되어 있지 않습니다 (pip install pycryptodome)")
    if isinstance(jwk, str):
        jwk = json.loads(jwk)
    if not isinstance(jwk, dict) or jwk.get("kty") != "RSA" or "d" not in jwk:
        raise E2EError("RSA 개인키 JWK 가 아닙니다")
    comps = [_int(jwk["n"]), _int(jwk["e"]), _int(jwk["d"])]
    if jwk.get("p") and jwk.get("q"):
        comps += [_int(jwk["p"]), _int(jwk["q"])]
    return RSA.construct(tuple(comps), consistency_check=True)


def split_prefixed(s: str) -> tuple[str, bytes]:
    if len(s) < PREFIXED_B64_LEN:
        raise E2EError("E2EKey 길이가 짧습니다")
    prefix, data = s[:-PREFIXED_B64_LEN], b64(s[-PREFIXED_B64_LEN:])
    if len(data) != 256:
        raise E2EError("E2EKey 의 base64 부분이 256 B 가 아닙니다")
    return prefix, data


def room_key(priv, e2ekey: str) -> tuple[str, dict]:
    try:
        kid, data = split_prefixed(e2ekey)
    except E2EError:
        kid, data = "", b64(e2ekey)
    raw = PKCS1_OAEP.new(priv, hashAlgo=SHA256).decrypt(data)
    try:
        jwk = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        jwk = {"kty": "oct", "alg": "raw", "k": base64.urlsafe_b64encode(raw).decode().rstrip("=")}
    if not isinstance(jwk, dict) or "k" not in jwk:
        raise E2EError("복호화한 방 키가 JWK 형식이 아닙니다")
    return kid, jwk


def _aes_key(jwk: dict) -> bytes:
    if not isinstance(jwk, dict) or not isinstance(jwk.get("k"), str):
        raise E2EError("방 키 JWK 에 k 가 없습니다")
    return b64url(jwk["k"])


def decrypt_content(keys: dict[str, dict], content=None, msg: str | None = None) -> tuple[object, str, str]:
    if not AVAILABLE:
        raise E2EError("pycryptodome 이 설치되어 있지 않습니다")
    if isinstance(content, dict) and content.get("algorithm") == "rc.v2.aes-sha2":
        kid, iv, ct = content.get("kid", ""), b64(content.get("iv", "")), b64(content.get("ciphertext", ""))
        jwk = keys.get(kid) or keys.get("")
        if jwk is None:
            raise E2EError(f"키 ID {kid} 의 방 키가 없습니다")
        if len(ct) < 16:
            raise E2EError("암호문이 너무 짧습니다")
        c = AES.new(_aes_key(jwk), AES.MODE_GCM, nonce=iv)
        try:
            pt = c.decrypt_and_verify(ct[:-16], ct[-16:])
        except ValueError:
            raise E2EError("GCM 인증 태그가 맞지 않습니다 (키가 다르거나 암호문이 손상됨)")
        alg = "rc.v2 AES-256-GCM"
    else:
        s = msg if isinstance(msg, str) else (content.get("ciphertext") if isinstance(content, dict) else None)
        if not s or len(s) < 12:
            raise E2EError("암호문이 없습니다")
        kid, raw = s[:12], b64(s[12:])
        jwk = keys.get(kid) or keys.get("")
        if jwk is None:
            raise E2EError(f"키 ID {kid} 의 방 키가 없습니다")
        iv, ct = raw[:16], raw[16:]
        key = _aes_key(jwk)
        try:
            pt = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), 16)
        except ValueError:
            raise E2EError("AES-CBC 패딩이 맞지 않습니다 (키가 다름)")
        alg = "rc.v1 AES-CBC"
    try:
        return json.loads(pt.decode("utf-8")), alg, kid
    except (UnicodeDecodeError, ValueError):
        return pt.decode("utf-8", "replace"), alg, kid


def decrypt_file(data: bytes, key_jwk: dict, iv_b64: str) -> bytes:
    if not AVAILABLE:
        raise E2EError("pycryptodome 이 설치되어 있지 않습니다")
    iv = b64(iv_b64)
    return AES.new(_aes_key(key_jwk), AES.MODE_CTR, nonce=b"", initial_value=iv).decrypt(data)


def plaintext_summary(obj) -> tuple[str, list[dict]]:
    if isinstance(obj, str):
        return obj, []
    if not isinstance(obj, dict):
        return json.dumps(obj, ensure_ascii=False), []
    text = obj.get("msg")
    if text is None:
        text = obj.get("text", "")
    files = []
    for a in obj.get("attachments") or []:
        if not isinstance(a, dict):
            continue
        enc = a.get("encryption") if isinstance(a.get("encryption"), dict) else {}
        key = enc.get("key") if isinstance(enc.get("key"), dict) else {}
        files.append({"title": a.get("title", ""), "fileId": a.get("fileId", ""), "type": a.get("image_type") or a.get("type", ""),
                      "size": a.get("image_size") or a.get("size", ""), "key": key.get("k", ""), "key_alg": key.get("alg", ""),
                      "iv": enc.get("iv", ""), "sha256": (a.get("hashes") or {}).get("sha256", ""),
                      "link": a.get("title_link", "")})
    return str(text or ""), files

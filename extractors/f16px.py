import re
import sys
import os
import json
import base64
import time
from urllib.parse import urlparse
from concurrent.futures import ProcessPoolExecutor, as_completed

import requests
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Cipher import AES

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0"
_MASK = 0xFFFFFFFF


def b64url_decode(value):
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * ((-len(value)) % 4)
    return base64.b64decode(value)


def b64url_encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def int_to_b64url(value):
    return b64url_encode(int(value).to_bytes(32, "big"))


def pow_hash(data):
    e0, e1, e2, e3 = 1779033703, 3144134277, 1013904242, 2773480762
    M = _MASK

    def qr():
        nonlocal e0, e1, e2, e3
        e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 16) | (x >> 16)) & M
        e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 12) | (x >> 20)) & M
        e0 = (e0 + e1) & M; x = e3 ^ e0; e3 = ((x << 8) | (x >> 24)) & M
        e2 = (e2 + e3) & M; x = e1 ^ e2; e1 = ((x << 7) | (x >> 25)) & M

    for b in data:
        e0 = (e0 + b) & M
        e0 = ((e0 << 7) | (e0 >> 25)) & M
        qr()

    for _ in range(8):
        qr()

    BE, LT, DR, LR, HR = 512, 511, 2, 2654435761, 2246822519
    r = [0] * BE
    for i in range(BE):
        qr()
        r[i] = (e0 ^ e2) & M

    for _ in range(DR):
        for s in range(BE):
            a = r[s] & LT
            c = (r[s] + r[a]) & M
            c = ((c << 13) | (c >> 19)) & M
            c = (c ^ ((r[(s + 1) & LT] * LR) & M)) & M
            r[s] = c
            e0 = (e0 ^ c) & M
            qr()

    n = [0] * 8
    o = BE // 8
    for i in range(8):
        qr()
        s = e0
        a = i * o
        for cc in range(o):
            d = r[a + cc]
            s = (s + d) & M
            s = ((s << 5) | (s >> 27)) & M
            s = (s ^ ((d * HR) & M)) & M
        n[i] = (s ^ e2) & M

    return n


def lz_bits(words):
    bits = 0
    for n in words:
        if n == 0:
            bits += 32
            continue
        c = 0
        m = 0x80000000
        while m and not (n & m):
            c += 1
            m >>= 1
        return bits + c
    return bits


def _solve_pow_worker(nonce, difficulty, start, step, timeout=60.0):
    if difficulty <= 0:
        return "0"
    prefix = nonce + ":"
    started = time.time()
    s = start
    while time.time() - started < timeout:
        if lz_bits(pow_hash((prefix + str(s)).encode("latin-1"))) >= difficulty:
            return str(s)
        s += step
    return None


def solve_pow(nonce, difficulty, timeout=60.0):
    if difficulty <= 0:
        return "0"

    workers = max(2, min(os.cpu_count() or 2, 4))

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_solve_pow_worker, nonce, difficulty, i, workers, timeout)
            for i in range(workers)
        ]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                executor.shutdown(cancel_futures=True)
                return result
    return None


def aesgcm_open(key, iv, payload):
    tag = payload[-16:]
    ct = payload[:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        return cipher.decrypt_and_verify(ct, tag)
    except Exception:
        return None


def join_key_parts(parts, version):
    v = int(version)
    n = len(parts)
    ka = b64url_decode(parts[v - 1])
    kb = b64url_decode(parts[n - v])
    return ka + kb


def build_attest_payload(challenge):
    key = ECC.generate(curve="P-256")
    digest = SHA256.new(challenge["nonce"].encode())
    signature = DSS.new(key, "fips-186-3", encoding="binary").sign(digest)

    public_key = {
        "alg": "ES256", "crv": "P-256", "ext": True, "key_ops": ["verify"], "kty": "EC",
        "x": int_to_b64url(key.pointQ.x), "y": int_to_b64url(key.pointQ.y),
    }

    return {
        "viewer_id": "", "device_id": "",
        "challenge_id": challenge["challenge_id"], "nonce": challenge["nonce"],
        "signature": b64url_encode(signature), "public_key": public_key,
        "client": {
            "user_agent": UA, "pixel_ratio": 2, "screen_width": 1536, "screen_height": 960,
            "color_depth": 24, "languages": ["en-US", "en"], "timezone": "Europe/Rome",
            "hardware_concurrency": 8, "touch_points": 0, "pointer_type": "fine,hover",
            "extra": {"vendor": "", "appVersion": "5.0 (Windows)"},
        },
        "storage": {}, "attributes": {"entropy": "low"},
    }


def pick_best(sources):
    def label_key(s):
        try:
            return int(s.get("label", 0))
        except Exception:
            return 0
    return sorted(sources, key=label_key, reverse=True)[0]["url"]


def extract(url):
    parsed = urlparse(url)
    embed_host = parsed.netloc
    embed_origin = f"{parsed.scheme}://{parsed.netloc}"

    m = re.search(r"/e/([A-Za-z0-9]+)", parsed.path or "")
    if not m:
        raise RuntimeError("Invalid embed URL")
    code = m.group(1)
    embed_url = f"{embed_origin}/e/{code}"

    s = requests.Session()

    r = s.get(
        f"{embed_origin}/api/videos/{code}/embed/details",
        headers={"Accept": "application/json, text/plain, */*", "User-Agent": UA,
                 "Referer": embed_url, "Origin": embed_origin},
    )
    r.raise_for_status()
    details = r.json()

    frame = details.get("embed_frame_url") or embed_url
    api_origin = f"{urlparse(frame).scheme}://{urlparse(frame).netloc}"
    referer = frame

    common = {
        "Accept": "application/json, text/plain, */*", "Content-Type": "application/json",
        "User-Agent": UA, "Origin": api_origin, "Referer": referer,
        "X-Embed-Origin": embed_host, "X-Embed-Referer": embed_url, "X-Embed-Parent": embed_url,
    }

    r = s.get(f"{api_origin}/api/videos/{code}/embed/settings", headers=common)
    r.raise_for_status()
    try:
        captcha_required = bool(r.json().get("captcha_required"))
    except Exception:
        captcha_required = True

    r = s.post(f"{api_origin}/api/videos/access/challenge", headers=common, json={})
    r.raise_for_status()
    challenge = r.json()

    r = s.post(f"{api_origin}/api/videos/access/attest", headers=common,
               json=build_attest_payload(challenge))
    r.raise_for_status()
    attest = r.json()

    fingerprint = {
        "token": attest["token"], "viewer_id": attest["viewer_id"],
        "device_id": attest["device_id"], "confidence": attest["confidence"],
    }

    cookie = f"byse_viewer_id={fingerprint['viewer_id']}; byse_device_id={fingerprint['device_id']}"
    with_cookie = {**common, "Cookie": cookie}

    captcha_token = None
    if captcha_required:
        r = s.post(f"{api_origin}/api/videos/{code}/embed/captcha", headers=with_cookie,
                   json={"fingerprint": fingerprint})
        r.raise_for_status()
        cap = r.json()

        print(f"Solving PoW (difficulty={cap['pow_difficulty']})...", file=sys.stderr)
        solution = solve_pow(cap["pow_nonce"], cap["pow_difficulty"], timeout=60.0)
        if solution is None:
            raise RuntimeError("PoW solve timed out")

        r = s.post(f"{api_origin}/api/videos/{code}/embed/captcha/verify", headers=with_cookie,
                   json={"pow_token": cap["pow_token"], "solution": solution, "fingerprint": fingerprint})
        r.raise_for_status()
        verify = r.json()
        if verify.get("status") != "ok" or not verify.get("token"):
            raise RuntimeError(f"captcha verify failed ({verify})")
        captcha_token = verify["token"]

    playback_headers = dict(with_cookie)
    if captcha_token:
        playback_headers["X-Captcha-Token"] = captcha_token

    r = s.post(f"{api_origin}/api/videos/{code}/embed/playback", headers=playback_headers,
               json={"fingerprint": fingerprint})
    r.raise_for_status()
    data = r.json()
    if not data:
        raise RuntimeError("Empty playback response")

    out_headers = {
        "referer": referer, "origin": api_origin, "Accept-Language": "en-US,en;q=0.5",
        "Accept": "*/*", "User-Agent": UA,
    }

    if data.get("sources"):
        return {"destination_url": pick_best(data["sources"]), "request_headers": out_headers}

    pb = data.get("playback")
    if not pb:
        raise RuntimeError("No playback data")

    iv = b64url_decode(pb["iv"])
    key = join_key_parts(pb["key_parts"], pb["version"])
    payload = b64url_decode(pb["payload"])

    decrypted = aesgcm_open(key, iv, payload)
    if decrypted is None:
        raise RuntimeError("GCM authentication failed")

    sources = json.loads(decrypted.decode("utf-8", "ignore")).get("sources") or []
    if not sources:
        raise RuntimeError("No sources after decryption")

    return {"destination_url": pick_best(sources), "request_headers": out_headers}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 run_f16px.py <embed_url>")
        sys.exit(1)

    result = extract(sys.argv[1])
    print(json.dumps(result, indent=2))

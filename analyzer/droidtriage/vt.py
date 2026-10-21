"""VirusTotal v3 hash lookups (never uploads unless explicitly asked, with confirmation)."""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://www.virustotal.com/api/v3"
CACHE = os.path.join(os.path.expanduser("~"), ".cache", "droidtriage", "vt_cache.json")
SPACING = 15.5  # free tier: 4 requests / minute


class VirusTotal:
    def __init__(self, key: str):
        self.key = key
        self._last = 0.0
        try:
            with open(CACHE, encoding="utf-8") as fh:
                self.cache = json.load(fh)
        except (OSError, ValueError):
            self.cache = {}

    def _save(self):
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        with open(CACHE, "w", encoding="utf-8") as fh:
            json.dump(self.cache, fh)

    def _req(self, url, data=None, headers=None):
        wait = self._last + SPACING - time.time()
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()
        req = urllib.request.Request(url, data=data, headers={"x-apikey": self.key, "accept": "application/json", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, {}

    def lookup(self, sha256: str, max_age_days: int = 7) -> dict | None:
        c = self.cache.get(sha256)
        if c and time.time() - c.get("ts", 0) < max_age_days * 86400:
            return c
        code, body = self._req(f"{API}/files/{sha256}")
        if code == 404:
            res = {"malicious": -1, "total": 0, "label": None, "ts": time.time()}
        elif code == 200:
            a = body["data"]["attributes"]
            stats = a.get("last_analysis_stats", {})
            res = {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                   "total": sum(stats.values()), "ts": time.time(),
                   "label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label") or a.get("meaningful_name")}
        elif code == 429:
            raise RuntimeError("VirusTotal quota exceeded (429)")
        elif code == 401:
            raise RuntimeError("VirusTotal API key rejected (401)")
        else:
            return None
        self.cache[sha256] = res
        self._save()
        return res

    def upload(self, path: str) -> str:
        """Uploads a file. Caller MUST have obtained explicit human confirmation."""
        size = os.path.getsize(path)
        url = f"{API}/files"
        if size > 32 * 2**20:
            code, body = self._req(f"{API}/files/upload_url")
            url = body["data"]
        boundary = f"----droidtriage{int(time.time() * 1000)}"
        with open(path, "rb") as fh:
            payload = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{os.path.basename(path)}\"\r\n"
                       f"Content-Type: application/octet-stream\r\n\r\n").encode() + fh.read() + f"\r\n--{boundary}--\r\n".encode()
        code, body = self._req(url, payload, {"Content-Type": f"multipart/form-data; boundary={boundary}"})
        if code != 200:
            raise RuntimeError(f"upload failed: HTTP {code}")
        return body["data"]["id"]


def confirm_upload(desc: str, assume_yes: bool) -> bool:
    print("\n" + "=" * 70)
    print("You asked to UPLOAD a file to VirusTotal:\n  " + desc)
    print("Uploaded files are shared with security vendors and downloadable by VirusTotal premium users.")
    print("Never upload private/enterprise apps or anything that may contain personal data.")
    print("=" * 70)
    if assume_yes:
        print("--yes given: proceeding.")
        return True
    if not sys.stdin.isatty():
        print("Not an interactive terminal: refusing to upload without --yes.")
        return False
    return input("Type UPLOAD to confirm: ").strip() == "UPLOAD"

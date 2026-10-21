"""VirusTotal v3 client and the ``virustotal`` analyser.

Privacy contract: :meth:`VirusTotal.lookup` sends only a SHA-256. :meth:`VirusTotal.upload` sends file
content and is reachable only through ``droidtriage vt upload`` / ``analyze --vt-upload`` after
:func:`confirm_upload` (typed confirmation, or ``--yes``).

Free API tier: 4 requests/min, 500/day -> requests are spaced :data:`SPACING` seconds apart and
results cached in ``~/.cache/droidtriage/vt_cache.json`` for 7 days.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

from .console import console
from .model import Context
from .registry import analyzer

API = "https://www.virustotal.com/api/v3"
CACHE = os.environ.get("DROIDTRIAGE_VT_CACHE") or os.path.join(os.path.expanduser("~"), ".cache", "droidtriage", "vt_cache.json")
SPACING = 15.5  # free tier: 4 requests / minute


class VirusTotal:
    """Minimal v3 client with on-disk cache and request spacing."""
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
        """Verdict for a SHA-256: {malicious (-1 = unknown to VT), total, label}. Cached for ``max_age_days``."""
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
    """Explain what an upload means and require typing UPLOAD (or ``--yes``). Refuses on non-TTY stdin."""
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


@analyzer("virustotal", 30, "VirusTotal", "hash lookups of user/sideloaded APKs (cached, rate limited)")
def run_vt(ctx: Context) -> None:
    """Reuse DroidSentinel's verdicts, then look up the remaining hashes if an API key is set."""
    rep = ctx.ev.json("sentinel/report.json") or {}
    for v in (rep.get("monitor") or {}).get("virustotal", []):
        if v.get("sha256") and v.get("positives", -1) >= 0:
            ctx.vt[v["sha256"]] = {"malicious": v["positives"], "total": v.get("total", 0), "label": v.get("label"), "source": "sentinel"}
    if not ctx.opt.vt_key:
        ctx.coverage["virustotal"] = "skipped – no API key (--vt-key or VT_API_KEY)" + (f"; {len(ctx.vt)} verdicts from DroidSentinel" if ctx.vt else "")
        return
    todo = []
    for name, p in ctx.packages.items():
        h = p.get("apkSha256")
        if not h:
            continue
        side = ctx.is_sideloaded(name)
        if ctx.opt.vt_scope == "all" or (ctx.opt.vt_scope == "user" and not p.get("system")) or side:
            todo.append((0 if side else 1, name, h))      # sideloaded first
    todo = sorted(todo)[: ctx.opt.vt_max]
    client = VirusTotal(ctx.opt.vt_key)
    uncached = sum(1 for _, _, h in todo if h not in client.cache)
    console.info(f"VirusTotal: {len(todo)} hashes, {uncached} not cached (≈{uncached * SPACING / 60:.0f} min on the free tier)")
    n = 0
    try:
        for _, _, h in todo:
            r = client.lookup(h)
            if r:
                ctx.vt[h] = r
                n += 1
    except RuntimeError as e:
        console.warn(f"VirusTotal stopped: {e}")
    ctx.coverage["virustotal"] = f"ok – {n} hashes looked up (hash only, nothing uploaded)"

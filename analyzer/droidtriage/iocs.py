"""Indicator-of-compromise loading.

Supported formats (put files in ./iocs or pass --ioc):
  * stalkerware-indicators ioc.yaml  (AssoEchap)  - packages, cert SHA-1, domains, IPs
  * STIX2 bundles (*.stix2 / *.json)  (MVT / Amnesty / Citizen Lab) - app ids, domains, hashes
  * plain text: one `type:value` per line (package:, domain:, ip:, sha256:, cert:)
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

from .console import console

ECHAP_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
MVT_INDEX = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


class IocDb:
    """In-memory indicator sets; values map to the family name used in findings."""
    def __init__(self):
        self.packages: dict[str, str] = {}
        self.cert_sha1: dict[str, str] = {}
        self.domains: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self.hashes: dict[str, str] = {}
        self.sources: list[str] = []

    def __len__(self):
        return sum(map(len, (self.packages, self.cert_sha1, self.domains, self.ips, self.hashes)))

    # ------------------------------------------------------------------ loading
    def load_path(self, path: str) -> None:
        """Load a file or every file of a folder, by extension (.yaml/.yml, .stix2/.json, .txt)."""
        if os.path.isdir(path):
            for f in sorted(os.listdir(path)):
                self.load_path(os.path.join(path, f))
            return
        low = path.lower()
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                data = fh.read()
        except OSError:
            return
        before = len(self)
        if low.endswith((".yaml", ".yml")):
            self._yaml(data, os.path.basename(path))
        elif low.endswith((".stix2", ".json")):
            self._stix(data, os.path.basename(path))
        elif low.endswith(".txt"):
            self._txt(data, os.path.splitext(os.path.basename(path))[0])
        if len(self) > before:
            self.sources.append(f"{os.path.basename(path)} (+{len(self) - before})")

    def _put_domain_or_ip(self, v: str, fam: str) -> None:
        v = v.strip().lower().strip("'\"")
        if not v:
            return
        (self.ips if IPV4.match(v) else self.domains)[v] = fam

    def _yaml(self, data: str, src: str) -> None:
        """Line parser for the stalkerware-indicators layout (PyYAML not required)."""
        family, key = src, ""
        for raw in data.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip())
            line = raw.strip()
            if indent == 0 and line.startswith("- name:"):
                family, key = line[7:].strip().strip("'\""), ""
                continue
            if not line.startswith("-") and ":" in line:
                key = line.split(":", 1)[0].strip()
                continue
            if line.startswith("- "):
                v = line[2:].strip().strip("'\"")
                if key == "packages":
                    self.packages[v] = family
                elif key == "certificates":
                    self.cert_sha1[v.lower()] = family
                elif key in ("websites", "domains", "distribution"):
                    self._put_domain_or_ip(v, family)
                elif key in ("ips", "ip"):
                    self.ips[v] = family
                elif key == "sha256":
                    self.hashes[v.lower()] = family

    def _stix(self, data: str, src: str) -> None:
        try:
            bundle = json.loads(data)
        except ValueError:
            return
        objs = bundle.get("objects", []) if isinstance(bundle, dict) else []
        names = {o["id"]: o.get("name", src) for o in objs if o.get("type") == "malware"}
        rel = {}
        for o in objs:
            if o.get("type") == "relationship" and o.get("relationship_type") == "indicates":
                rel[o.get("source_ref")] = names.get(o.get("target_ref"), src)
        for o in objs:
            if o.get("type") != "indicator":
                continue
            fam = rel.get(o.get("id"), names and next(iter(names.values())) or src)
            for kind, value in re.findall(r"\[([\w:.\-']+)\s*=\s*'([^']+)'\]", o.get("pattern", "")):
                kind = kind.lower()
                if kind in ("app:id",):
                    self.packages[value] = fam
                elif kind in ("domain-name:value", "url:value"):
                    host = re.sub(r"^\w+://", "", value).split("/")[0]
                    self._put_domain_or_ip(host, fam)
                elif kind in ("ipv4-addr:value",):
                    self.ips[value] = fam
                elif "sha256" in kind:
                    self.hashes[value.lower()] = fam
                elif kind in ("app:cert.sha1", "x509-certificate:hashes.'sha-1'"):
                    self.cert_sha1[value.lower()] = fam

    def _txt(self, data: str, fam: str) -> None:
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            t, v = line.split(":", 1)
            t, v = t.strip().lower(), v.strip()
            if t == "package":
                self.packages[v] = fam
            elif t == "domain":
                self.domains[v.lower()] = fam
            elif t == "ip":
                self.ips[v] = fam
            elif t == "sha256":
                self.hashes[v.lower()] = fam
            elif t in ("cert", "cert_sha1"):
                self.cert_sha1[v.lower()] = fam

    # ------------------------------------------------------------------ matching
    def match_domain(self, domain: str) -> str | None:
        """Return the family if ``domain`` or any parent domain is an indicator."""
        d = domain.lower().rstrip(".")
        while d:
            if d in self.domains:
                return self.domains[d]
            if "." not in d:
                return None
            d = d.split(".", 1)[1]
        return None


def update(dest: str) -> None:
    """Explicit, user-requested download of public IOC feeds. Sends no data about the device."""
    os.makedirs(dest, exist_ok=True)

    def fetch(url, name):
        console.info(f"downloading {url}")
        try:
            with urllib.request.urlopen(url, timeout=60) as r:
                data = r.read()
            with open(os.path.join(dest, name), "wb") as fh:
                fh.write(data)
            return data.decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001
            console.warn(f"failed: {url}: {e}")
            return ""

    fetch(ECHAP_URL, "stalkerware-indicators.yaml")
    index = fetch(MVT_INDEX, "_mvt_index.yaml")
    # Minimal parse of the MVT index: owner/repo/branch/path blocks or download_url.
    cur: dict[str, str] = {}
    entries = []
    for line in index.splitlines() + ["  -"]:
        s = line.strip()
        if s == "-":
            if cur:
                entries.append(cur)
            cur = {}
            continue
        m = re.match(r"(\w+):\s*(.+)$", s)
        if m and m.group(1) in ("owner", "repo", "branch", "path", "download_url", "name"):
            cur[m.group(1)] = m.group(2).strip()
    for e in entries:
        if "download_url" in e:
            url = e["download_url"]
        elif all(k in e for k in ("owner", "repo", "branch", "path")):
            url = f"https://raw.githubusercontent.com/{e['owner']}/{e['repo']}/{e['branch']}/{e['path']}"
        else:
            continue
        fetch(url, "mvt_" + os.path.basename(url))
    try:
        os.remove(os.path.join(dest, "_mvt_index.yaml"))
    except OSError:
        pass

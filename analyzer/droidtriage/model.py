"""Shared data model: findings, severities and the analysis context."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
WEIGHT = {"INFO": 0, "LOW": 1, "MEDIUM": 5, "HIGH": 15, "CRITICAL": 40}
CATEGORIES = ["PRIVACY", "SECURITY", "SUSPICIOUS", "UNKNOWN", "MALWARE"]


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    detail: str = ""
    package: str | None = None
    mitre: str | None = None
    source: str = ""                      # which analyser produced it
    evidence: list[str] = field(default_factory=list)

    def key(self) -> tuple:
        return (self.id, self.package, self.title)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEvent:
    ts: str            # ISO-ish sortable string
    source: str
    what: str
    package: str | None = None
    severity: str = "INFO"


class Context:
    """Everything the analysers share. Analysers append findings / timeline entries."""

    def __init__(self, evidence, iocs, options):
        self.ev = evidence
        self.iocs = iocs
        self.opt = options
        self.findings: list[Finding] = []
        self.timeline: list[TimelineEvent] = []
        self.packages: dict[str, dict] = {}       # package -> normalised record
        self.apk_reports: dict[str, dict] = {}    # package -> static analysis result
        self.device: dict[str, Any] = {}
        self.enabled = {"accessibility": set(), "notification": set(), "admins": set(),
                        "ime": None, "sms": None, "autofill": None, "device_owner": None}
        self.vt: dict[str, dict] = {}
        self.coverage: dict[str, str] = {}        # analysis -> "ok" | reason skipped
        self.log_hits: dict[str, dict] = {}
        self.network: dict[str, Any] = {}
        self.sentinel: dict | None = None

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def event(self, ts, source, what, package=None, severity="INFO"):
        self.timeline.append(TimelineEvent(str(ts), source, what, package, severity))

    def is_sideloaded(self, pkg: str) -> bool:
        p = self.packages.get(pkg)
        if not p or p.get("system"):
            return False
        return p.get("installer") not in self.opt.trusted_installers

    def dedupe(self) -> None:
        seen, out = set(), []
        for f in self.findings:
            if f.key() in seen:
                continue
            seen.add(f.key())
            out.append(f)
        out.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.category, f.package or ""))
        self.findings = out

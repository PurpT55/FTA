"""Shared data model: severities, findings, timeline events, options and the analysis context.

Every analyser receives one :class:`Context` and communicates only through it:

* ``ctx.add(Finding(...))``  -> a detection shown in the report
* ``ctx.event(ts, ...)``     -> an entry in the forensic timeline
* ``ctx.coverage[name]``     -> what the analyser could / could not see ("ok ..." or a reason)

Keeping that contract small is what makes new analysers cheap to add (see ``registry.py``).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
#: Contribution of one finding to the 0-100 security score.
WEIGHT = {"INFO": 0, "LOW": 1, "MEDIUM": 5, "HIGH": 15, "CRITICAL": 40}
#: Dashboard buckets (same names as the on-device DroidSentinel dashboard).
CATEGORIES = ["PRIVACY", "SECURITY", "SUSPICIOUS", "UNKNOWN", "MALWARE"]


def sev_rank(sev: str) -> int:
    """INFO=0 ... CRITICAL=4; unknown values rank as INFO."""
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


@dataclass
class Finding:
    """One detection. ``id`` is a stable dotted identifier (``family.rule``) used for de-duplication,
    baseline diffs and the playbook (advice is matched by id prefix)."""

    id: str
    severity: str
    category: str
    title: str
    detail: str = ""
    package: str | None = None
    mitre: str | None = None
    source: str = ""                      # analyser that produced it
    evidence: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r} for {self.id}")
        if self.category not in CATEGORIES:
            raise ValueError(f"bad category {self.category!r} for {self.id}")

    def key(self) -> tuple:
        """Identity used for de-duplication and baseline comparison."""
        return (self.id, self.package, self.title)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable dict."""
        return asdict(self)


@dataclass
class TimelineEvent:
    """One row of the forensic timeline."""
    ts: str            # normalised "YYYY-MM-DD HH:MM:SS" when parseable, raw otherwise
    source: str
    what: str
    package: str | None = None
    severity: str = "INFO"


@dataclass
class Options:
    """Analysis options (filled by the CLI, or directly when used as a library)."""

    trusted_installers: set[str] = field(default_factory=set)
    vt_key: str | None = None
    vt_scope: str = "user"            # sideloaded | user | all
    vt_max: int = 200
    max_apk_mb: int = 300
    jobs: int = 1                     # parallel APK workers
    skip: set[str] = field(default_factory=set)   # analyser names to skip
    verbose: bool = False


_LOGCAT_TS = re.compile(r"^(\d\d)-(\d\d)\s+(\d\d:\d\d:\d\d)")
_ISO_TS = re.compile(r"^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)")


def norm_ts(ts: Any, ref: datetime | None = None) -> str:
    """Normalise the many timestamp formats found in Android evidence to ``YYYY-MM-DD HH:MM:SS``.

    Handles epoch seconds/milliseconds, ISO-8601, ``YYYY-MM-DD HH:MM:SS.fff`` (dumpsys) and
    year-less logcat stamps ``MM-DD HH:MM:SS.fff`` (the year is taken from ``ref``, the collection
    date, going back one year when the date would be in the future). Unknown formats are returned as is.
    """
    if ts is None or ts == "":
        return ""
    if isinstance(ts, (int, float)) or (isinstance(ts, str) and ts.isdigit() and len(ts) in (10, 13)):
        v = float(ts)
        if v > 1e12:
            v /= 1000.0
        return datetime.fromtimestamp(v, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    s = str(ts).strip()
    m = _ISO_TS.match(s)
    if m:
        return f"{m.group(1)} {m.group(2)}"
    m = _LOGCAT_TS.match(s)
    if m:
        ref = ref or datetime.now(timezone.utc).replace(tzinfo=None)
        year = ref.year
        if (int(m.group(1)), int(m.group(2))) > (ref.month, ref.day):
            year -= 1
        return f"{year}-{m.group(1)}-{m.group(2)} {m.group(3)}"
    return s


class Context:
    """Everything the analysers share. Analysers append findings / timeline entries."""

    def __init__(self, evidence, iocs, options: Options):
        self.ev = evidence
        self.iocs = iocs
        self.opt = options
        self.findings: list[Finding] = []
        self.timeline: list[TimelineEvent] = []
        self.packages: dict[str, dict] = {}       # package -> normalised record (see packages.py)
        self.apk_reports: dict[str, dict] = {}    # package -> static analysis result (see apk.py)
        self.device: dict[str, Any] = {}          # posture, props, roles, appops usage...
        self.enabled = {"accessibility": set(), "notification": set(), "admins": set(),
                        "ime": None, "sms": None, "autofill": None, "device_owner": None}
        self.vt: dict[str, dict] = {}             # sha256 -> {"malicious", "total", "label"}
        self.coverage: dict[str, str] = {}        # analyser -> "ok ..." | reason it is limited
        self.log_hits: dict[str, dict] = {}
        self.network: dict[str, Any] = {}
        self.sentinel: dict | None = None
        self.unknown: list[str] = []              # sideloaded and unknown to VirusTotal
        self.scores: dict[str, dict] = {}         # package -> {"privacy", "security"}
        self.prev_keys: set | None = None         # finding keys of a --baseline report
        self.timings: dict[str, float] = {}
        manifest = evidence.json("manifest.json", {}) or {}
        self.collected_at = _parse_iso(manifest.get("startedAt")) or datetime.now(timezone.utc).replace(tzinfo=None)

    # ------------------------------------------------------------------ recording
    def add(self, f: Finding) -> None:
        """Record a finding."""
        self.findings.append(f)

    def event(self, ts, source: str, what: str, package: str | None = None, severity: str = "INFO") -> None:
        """Record a timeline entry; ``ts`` is normalised with :func:`norm_ts`."""
        self.timeline.append(TimelineEvent(norm_ts(ts, self.collected_at), source, what, package, severity))

    # ------------------------------------------------------------------ helpers
    def is_sideloaded(self, pkg: str) -> bool:
        """True for a non-system app whose installer is not in the trusted set."""
        p = self.packages.get(pkg)
        if not p or p.get("system"):
            return False
        return p.get("installer") not in self.opt.trusted_installers

    def dedupe(self) -> None:
        """Drop duplicate findings and sort by severity (desc), category, package."""
        seen, out = set(), []
        for f in self.findings:
            if f.key() in seen:
                continue
            seen.add(f.key())
            out.append(f)
        out.sort(key=lambda f: (-sev_rank(f.severity), f.category, f.package or ""))
        self.findings = out


def _parse_iso(s):
    if not s:
        return None
    try:
        return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def utcnow() -> datetime:
    """Naive UTC now (``datetime.utcnow`` is deprecated since 3.12)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

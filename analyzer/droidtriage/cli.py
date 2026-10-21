"""Command-line interface.

    droidtriage analyze EVIDENCE [options]     full analysis -> report.html / report.json / CSV
    droidtriage apk FILE.apk [...]            static analysis of standalone APKs
    droidtriage diff OLD.json NEW.json         compare two reports
    droidtriage iocs {update,stats,check}      manage indicator feeds
    droidtriage vt {lookup,upload}             VirusTotal (hash lookups; uploads need confirmation)
    droidtriage sample OUT.zip                 synthetic evidence for a demo
    droidtriage rules                          list analysers and detection rules

``droidtriage EVIDENCE`` (no sub-command) is kept as a shortcut for ``analyze``.
Exit codes of ``analyze``: 0 nothing above --fail-on, 1 HIGH findings, 2 malware indicators, 3 usage/IO error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import webbrowser

from . import __version__
from .console import console
from .model import SEVERITIES, Options, sev_rank

TRUSTED = ["com.android.vending", "com.sec.android.app.samsungapps", "com.huawei.appmarket", "com.xiaomi.mipicks",
           "com.xiaomi.market", "com.amazon.venezia", "com.oppo.market", "com.heytap.market", "com.bbk.appstore", "org.fdroid.fdroid"]
REPO_IOCS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "iocs")
COMMANDS = ("analyze", "apk", "diff", "iocs", "vt", "sample", "rules")


def default_ioc_dir() -> str:
    """$DROIDTRIAGE_IOCS, else analyzer/iocs when running from the repo, else ~/.local/share/droidtriage/iocs."""
    if os.environ.get("DROIDTRIAGE_IOCS"):
        return os.environ["DROIDTRIAGE_IOCS"]
    if os.path.isdir(REPO_IOCS):
        return REPO_IOCS
    return os.path.join(os.path.expanduser("~"), ".local", "share", "droidtriage", "iocs")


def load_iocs(extra: list[str], use_default: bool = True):
    """Load the default IOC folder (unless disabled) plus ``extra`` paths."""
    from .iocs import IocDb
    db = IocDb()
    for p in ([default_ioc_dir()] if use_default else []) + list(extra):
        if os.path.exists(p):
            db.load_path(p)
        elif p in extra:
            console.warn(f"IOC path not found: {p}")
    return db


# --------------------------------------------------------------------------- parser
EXAMPLES = """examples:
  droidtriage iocs update                               # once: stalkerware + MVT spyware feeds
  droidtriage analyze droidcollect_Pixel.zip            # -> droidcollect_Pixel_report/report.html
  droidtriage analyze evidence/ -o out --open           # adb_collect.sh folder, open the report
  VT_API_KEY=... droidtriage analyze e.zip --vt-scope sideloaded
  droidtriage analyze new.zip --baseline old_report/report.json --fail-on malware
  droidtriage analyze e.zip --json -q | jq .summary     # machine-readable summary on stdout
  droidtriage apk suspicious.apk --json
  droidtriage diff old/report.json new/report.json
  droidtriage sample demo.zip && droidtriage analyze demo.zip
"""


def build_parser() -> argparse.ArgumentParser:
    """Argument parser with one sub-parser per command; console flags are shared via a parent parser."""
    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("console")
    g.add_argument("-q", "--quiet", action="store_true", help="only print results and errors")
    g.add_argument("-v", "--verbose", action="store_true", help="debug output (timings, skipped items)")
    g.add_argument("--no-color", action="store_true", help="disable ANSI colours (also: NO_COLOR env var)")

    ap = argparse.ArgumentParser(prog="droidtriage", description="Offline Android forensic triage of DroidCollector / adb_collect.sh evidence.",
                                 epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter, parents=[common])
    ap.add_argument("--version", action="version", version=f"droidtriage {__version__}")
    sub = ap.add_subparsers(dest="command", metavar="COMMAND")

    # analyze ---------------------------------------------------------------
    a = sub.add_parser("analyze", parents=[common], help="analyse an evidence zip or folder",
                       description="Run every analyser on the evidence and write the reports.",
                       epilog=EXAMPLES, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("evidence", help="DroidCollector .zip, extracted folder, or adb_collect.sh folder")
    o = a.add_argument_group("output")
    o.add_argument("-o", "--out", help="output directory (default: <evidence>_report)")
    o.add_argument("-f", "--format", default="html,json,csv", help="comma list of html,json,csv (default: all)")
    o.add_argument("--open", action="store_true", help="open report.html in the browser when done")
    o.add_argument("--json", action="store_true", help="print the summary + findings as JSON on stdout")
    o.add_argument("--top", type=int, default=15, metavar="N", help="findings shown in the console summary (default 15)")
    o.add_argument("--min-severity", choices=SEVERITIES, default="HIGH", help="lowest severity shown in the console (default HIGH)")
    o.add_argument("--fail-on", choices=["never", "high", "malware"], default="high",
                   help="exit 1 on HIGH / 2 on malware (high), only 2 (malware), or always 0 (never)")
    i = a.add_argument_group("intelligence")
    i.add_argument("--ioc", action="append", default=[], metavar="PATH", help="extra IOC file or folder (repeatable)")
    i.add_argument("--no-default-iocs", action="store_true", help=f"do not load {default_ioc_dir()}")
    i.add_argument("--trusted-installer", action="append", default=[], metavar="PKG", help="treat this installer as a trusted store (repeatable)")
    i.add_argument("--baseline", metavar="REPORT_JSON", help="previous report.json: flag new/changed apps, mark NEW findings")
    v = a.add_argument_group("VirusTotal (hash lookups only)")
    v.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"), help="API key (default: $VT_API_KEY)")
    v.add_argument("--vt-scope", choices=["sideloaded", "user", "all"], default="user", help="which apps to look up (default user)")
    v.add_argument("--vt-max", type=int, default=200, metavar="N", help="max lookups this run (free tier: 500/day)")
    v.add_argument("--vt-upload", action="append", default=[], metavar="PKG", help="UPLOAD this package's APK after typed confirmation")
    v.add_argument("--yes", action="store_true", help="skip the typed confirmation of --vt-upload (scripts)")
    p = a.add_argument_group("performance / scope")
    p.add_argument("-j", "--jobs", type=int, default=min(4, os.cpu_count() or 1), help="parallel APK workers (default min(4, CPUs))")
    p.add_argument("--max-apk-mb", type=int, default=300, metavar="MB", help="skip static analysis of larger APKs (default 300)")
    p.add_argument("--skip", default="", metavar="NAMES", help="comma list of analysers to skip (see `droidtriage rules`)")
    a.add_argument("--update-iocs", action="store_true", help=argparse.SUPPRESS)   # v1 compatibility

    # apk ---------------------------------------------------------------------
    k = sub.add_parser("apk", parents=[common], help="static analysis of standalone APK files")
    k.add_argument("files", nargs="+", help="APK files")
    k.add_argument("--json", action="store_true", help="full JSON result on stdout")
    k.add_argument("--ioc", action="append", default=[], metavar="PATH", help="extra IOC file or folder")

    # diff --------------------------------------------------------------------
    d = sub.add_parser("diff", parents=[common], help="compare two report.json files")
    d.add_argument("old")
    d.add_argument("new")
    d.add_argument("--json", action="store_true", help="JSON on stdout")

    # iocs --------------------------------------------------------------------
    c = sub.add_parser("iocs", parents=[common], help="manage IOC feeds")
    csub = c.add_subparsers(dest="ioc_cmd", metavar="ACTION", required=True)
    cu = csub.add_parser("update", parents=[common], help="download stalkerware-indicators + MVT STIX2 feeds")
    cu.add_argument("--dest", default=default_ioc_dir(), help=f"target folder (default {default_ioc_dir()})")
    csub.add_parser("stats", parents=[common], help="show loaded feeds and counts").add_argument("--ioc", action="append", default=[])
    cc = csub.add_parser("check", parents=[common], help="check packages / domains / hashes / IPs against the feeds")
    cc.add_argument("values", nargs="+")
    cc.add_argument("--ioc", action="append", default=[])

    # vt ----------------------------------------------------------------------
    t = sub.add_parser("vt", parents=[common], help="VirusTotal lookups / confirmed uploads")
    tsub = t.add_subparsers(dest="vt_cmd", metavar="ACTION", required=True)
    tl = tsub.add_parser("lookup", parents=[common], help="look up SHA-256 hashes (or files: only their hash is sent)")
    tl.add_argument("items", nargs="+")
    tl.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"))
    tu = tsub.add_parser("upload", parents=[common], help="UPLOAD a file (typed confirmation required)")
    tu.add_argument("file")
    tu.add_argument("--vt-key", default=os.environ.get("VT_API_KEY"))
    tu.add_argument("--yes", action="store_true", help="skip the typed confirmation")

    # sample / rules -------------------------------------------------------------
    s = sub.add_parser("sample", parents=[common], help="write synthetic evidence with planted indicators")
    s.add_argument("out", help="output .zip")
    s.add_argument("--apk", help="real APK to embed so static analysis runs too")
    r = sub.add_parser("rules", parents=[common], help="list analysers and detection rules")
    r.add_argument("--json", action="store_true")
    return ap


def _normalise_argv(argv: list[str]) -> list[str]:
    """v1 compatibility: ``droidtriage X.zip`` -> analyze, ``--update-iocs`` alone -> iocs update."""
    if argv == ["--update-iocs"]:
        return ["iocs", "update"]
    pos = [x for x in argv if not x.startswith("-")]
    if pos and pos[0] not in COMMANDS and argv and argv[0] not in ("-h", "--help", "--version"):
        return ["analyze"] + argv
    return argv


# --------------------------------------------------------------------------- commands
def cmd_analyze(a) -> int:
    """``droidtriage analyze``: run the pipeline, write reports, optional confirmed uploads, exit code by --fail-on."""
    from .baseline import compare
    from .evidence import Evidence
    from .model import Context
    from .pipeline import run_all
    from .registry import REGISTRY
    from .report import FORMATS, write_all
    from .vt import VirusTotal, confirm_upload

    if a.update_iocs:
        cmd_iocs_update(argparse.Namespace(dest=default_ioc_dir()))
    formats = {f.strip() for f in a.format.split(",") if f.strip()}
    if not formats <= set(FORMATS):
        console.error(f"--format must be among {','.join(FORMATS)}")
        return 3
    skip = {x.strip() for x in a.skip.split(",") if x.strip()}
    import droidtriage.pipeline  # noqa: F401  (registers analysers)
    unknown = skip - set(REGISTRY)
    if unknown:
        console.error(f"unknown analyser(s) for --skip: {', '.join(sorted(unknown))}; valid: {', '.join(sorted(REGISTRY))}")
        return 3
    try:
        ev = Evidence(a.evidence)
    except (ValueError, OSError) as e:
        console.error(str(e))
        return 3
    iocs = load_iocs(a.ioc, not a.no_default_iocs)
    if not len(iocs):
        console.warn("no IOC feeds loaded – run `droidtriage iocs update` once for stalkerware/spyware indicators")
    opt = Options(trusted_installers=set(TRUSTED + a.trusted_installer), vt_key=a.vt_key, vt_scope=a.vt_scope,
                  vt_max=a.vt_max, max_apk_mb=a.max_apk_mb, jobs=max(1, a.jobs), skip=skip, verbose=a.verbose)
    console.step(f"droidtriage {__version__} · {a.evidence} · {len(iocs)} IOCs")
    ctx = run_all(Context(ev, iocs, opt))
    if a.baseline:
        compare(ctx, a.baseline)
    out = a.out or (a.evidence.rstrip("/\\").rsplit(".zip", 1)[0] + "_report")
    data = write_all(ctx, out, formats)

    for pkg in a.vt_upload:
        if not a.vt_key:
            console.error("--vt-upload needs --vt-key / VT_API_KEY")
            break
        name = f"apks/{pkg}/base.apk"
        if not ev.has(name):
            console.error(f"{pkg}: no base.apk in the evidence")
            continue
        sha = ctx.packages.get(pkg, {}).get("apkSha256")
        if not confirm_upload(f"{pkg} ({ev.size(name) / 2**20:.1f} MB) sha256={sha}", a.yes):
            console.info("upload cancelled")
            continue
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, f"{pkg}.apk")
            with open(path, "wb") as fh:
                fh.write(ev.read(name))
            console.info(f"analysis id: {VirusTotal(a.vt_key).upload(path)}")

    if a.json:
        json.dump({"summary": data["summary"], "coverage": data["coverage"], "findings": data["findings"]}, sys.stdout, indent=1, default=str)
        print()
    else:
        print_summary(data, out, formats, a.top, a.min_severity)
    if a.open and "html" in formats:
        webbrowser.open("file://" + os.path.abspath(os.path.join(out, "report.html")))
    s = data["summary"]
    if a.fail_on == "never":
        return 0
    if s["malware"]:
        return 2
    if a.fail_on == "high" and s["bySeverity"].get("HIGH", 0) + s["bySeverity"].get("CRITICAL", 0):
        return 1
    return 0


def print_summary(data: dict, out: str, formats, top: int, min_sev: str) -> None:
    """Coloured console summary: scores, top findings, coverage, output paths."""
    s = data["summary"]
    c = console.c
    col = lambda v: "bad" if v >= 60 else "warn" if v >= 15 else "ok"  # noqa: E731
    print()
    print(c(" Privacy risk ", "dim") + c(f"{s['privacyRisk']}/100", col(s["privacyRisk"])) + c("   Security risk ", "dim")
          + c(f"{s['securityRisk']}/100", col(s["securityRisk"])) + c("   Suspicious ", "dim") + c(str(s["suspicious"]), "warn" if s["suspicious"] else "ok")
          + c("   Unknown binaries ", "dim") + c(str(len(s["unknownBinaries"])), "warn" if s["unknownBinaries"] else "ok")
          + c("   Malware ", "dim") + c(str(len(s["malware"])), "bad" if s["malware"] else "ok"))
    print(c(" by severity: ", "dim") + "  ".join(c(f"{k} {v}", k) for k, v in reversed(list(s["bySeverity"].items()))))
    shown = [f for f in data["findings"] if sev_rank(f["severity"]) >= sev_rank(min_sev)][:top]
    if shown:
        print()
        console.table([[c(f["severity"], f["severity"]), (f["package"] or "device")[:42], f["title"][:90]] for f in shown],
                      ["SEVERITY", "PACKAGE", "FINDING"])
        rest = sum(1 for f in data["findings"] if sev_rank(f["severity"]) >= sev_rank(min_sev)) - len(shown)
        if rest > 0:
            print(c(f" … {rest} more (see report or --top)", "dim"))
    print()
    console.table([[k, c(v, "ok" if v.startswith("ok") else "warn")] for k, v in data["coverage"].items()], ["COVERAGE", ""])
    print()
    for f in sorted(formats):
        target = {"html": "report.html", "json": "report.json", "csv": "findings.csv, apps.csv, timeline.csv"}[f]
        print(c(f" {f:5}", "bold") + f" {os.path.join(out, target) if f != 'csv' else out + '/ ' + target}")


def cmd_apk(a) -> int:
    """``droidtriage apk``: static analysis of standalone APKs + IOC check. Exit 2 on IOC hit."""
    from .apk import analyse_apk
    iocs = load_iocs(a.ioc)
    results = []
    for f in a.files:
        try:
            with open(f, "rb") as fh:
                rep = analyse_apk(fh.read(), f)
        except OSError as e:
            console.error(f"{f}: {e}")
            return 3
        m = rep.get("manifest") or {}
        hits = []
        if m.get("package") in iocs.packages:
            hits.append(f"package:{iocs.packages[m['package']]}")
        hits += [f"cert:{iocs.cert_sha1[c['sha1']]}" for c in rep["certs"] if c["sha1"] in iocs.cert_sha1]
        if rep["sha256"] in iocs.hashes:
            hits.append(f"hash:{iocs.hashes[rep['sha256']]}")
        hits += [f"domain:{h}" for h in rep.get("hosts", []) if iocs.match_domain(h)]
        rep["ioc_hits"] = hits
        results.append(rep)
    if a.json:
        json.dump(results if len(results) > 1 else results[0], sys.stdout, indent=1, default=str)
        print()
        return 2 if any(r["ioc_hits"] for r in results) else 0
    c = console.c
    for rep in results:
        m = rep.get("manifest") or {}
        print(c(f"\n{rep['file']}", "title"))
        rows = [["package", f"{m.get('package')} {m.get('versionName') or ''}"], ["sha256", rep["sha256"]],
                ["size", f"{rep['size'] / 2**20:.1f} MB, {rep['dex_count']} dex"], ["sdk", f"min {m.get('sdk', {}).get('min')} target {m.get('sdk', {}).get('target')}"],
                ["signers", "; ".join(f"{x['scheme']} {x['sha256'][:16]}… {x['subject']}" for x in rep["certs"]) or "none"],
                ["permissions", str(len(m.get("permissions", [])))], ["components", str(len(m.get("components", [])))],
                ["trackers", ", ".join(rep["trackers"]) or "–"], ["hosts", ", ".join(rep.get("hosts", [])[:12]) or "–"],
                ["IOC", c(", ".join(rep["ioc_hits"]), "bad") if rep["ioc_hits"] else c("no match", "ok")]]
        console.table(rows)
        fs = sorted(rep["findings"], key=lambda x: -sev_rank(x["severity"]))
        if fs:
            console.table([[c(x["severity"], x["severity"]), x["title"], x.get("mitre") or ""] for x in fs], ["SEVERITY", "FINDING", "ATT&CK"])
        for e in rep["errors"]:
            console.warn(e)
    return 2 if any(r["ioc_hits"] for r in results) else 0


def cmd_diff(a) -> int:
    """``droidtriage diff``: apps added/removed/changed, new/resolved findings, score deltas."""
    from .baseline import diff_reports
    try:
        with open(a.old, encoding="utf-8") as fh:
            old = json.load(fh)
        with open(a.new, encoding="utf-8") as fh:
            new = json.load(fh)
    except (OSError, ValueError) as e:
        console.error(str(e))
        return 3
    d = diff_reports(old, new)
    if a.json:
        json.dump(d, sys.stdout, indent=1, default=str)
        print()
        return 0
    c = console.c
    print(c("Scores (old → new): ", "bold") + ", ".join(f"{k} {v[0]} → {v[1]}" for k, v in d["scores"].items()))
    print(c(f"\nApps added ({len(d['apps_added'])}): ", "bold") + (", ".join(d["apps_added"]) or "–"))
    print(c(f"Apps removed ({len(d['apps_removed'])}): ", "bold") + (", ".join(d["apps_removed"]) or "–"))
    if d["apps_changed"]:
        print(c("\nApps changed:", "bold"))
        console.table([[x["package"], k, str(v[0])[:40], str(v[1])[:40]] for x in d["apps_changed"] for k, v in x["changes"].items()],
                      ["PACKAGE", "FIELD", "OLD", "NEW"])
    print(c(f"\nNew findings ({len(d['findings_new'])}):", "bold"))
    console.table([[c(f["severity"], f["severity"]), f.get("package") or "device", f["title"][:90]] for f in d["findings_new"]] or [["–", "", ""]])
    print(c(f"\nResolved findings: {len(d['findings_gone'])}", "bold"))
    return 0


def cmd_iocs_update(a) -> int:
    """Download public IOC feeds into ``a.dest`` and report the count."""
    from .iocs import update
    console.step(f"downloading IOC feeds into {a.dest}")
    update(a.dest)
    db = load_iocs([], True) if os.path.abspath(a.dest) == os.path.abspath(default_ioc_dir()) else load_iocs([a.dest], False)
    console.info(f"{len(db)} indicators from {len(db.sources)} file(s)")
    return 0


def cmd_iocs(a) -> int:
    """``droidtriage iocs {update,stats,check}``. ``check`` exits 2 when any value matches."""
    if a.ioc_cmd == "update":
        return cmd_iocs_update(a)
    db = load_iocs(a.ioc)
    if a.ioc_cmd == "stats":
        print(f"folder: {default_ioc_dir()}")
        console.table([[s] for s in db.sources] or [["(none – run `droidtriage iocs update`)"]], ["SOURCE (+indicators)"])
        console.table([["packages", len(db.packages)], ["signing certs (sha1)", len(db.cert_sha1)], ["domains", len(db.domains)],
                       ["ips", len(db.ips)], ["sha256", len(db.hashes)]], ["TYPE", "COUNT"])
        return 0
    hit = False
    for v in a.values:
        low = v.lower()
        r = (db.packages.get(v) and f"package · {db.packages[v]}") or (db.cert_sha1.get(low) and f"signing cert · {db.cert_sha1[low]}") \
            or (db.hashes.get(low) and f"sha256 · {db.hashes[low]}") or (db.ips.get(v) and f"ip · {db.ips[v]}") \
            or (db.match_domain(v) and f"domain · {db.match_domain(v)}")
        hit |= bool(r)
        print(f"{v}: " + (console.c(r, "bad") if r else console.c("no match", "ok")))
    return 2 if hit else 0


def cmd_vt(a) -> int:
    """``droidtriage vt lookup|upload``. Files given to lookup are hashed locally; only the hash is sent."""
    import hashlib
    from .vt import VirusTotal, confirm_upload
    if not a.vt_key:
        console.error("needs --vt-key or VT_API_KEY")
        return 3
    client = VirusTotal(a.vt_key)
    if a.vt_cmd == "upload":
        size = os.path.getsize(a.file)
        if not confirm_upload(f"{a.file} ({size / 2**20:.1f} MB)", a.yes):
            console.info("upload cancelled")
            return 0
        print("analysis id:", client.upload(a.file))
        return 0
    rows, worst = [], 0
    for item in a.items:
        h = item.lower()
        if os.path.isfile(item):
            with open(item, "rb") as fh:
                h = hashlib.sha256(fh.read()).hexdigest()       # only the hash leaves the machine
        try:
            r = client.lookup(h) or {}
        except RuntimeError as e:
            console.error(str(e))
            return 3
        m = r.get("malicious", -1)
        worst = max(worst, m)
        rows.append([item if item == h else f"{item} ({h[:12]}…)", "unknown" if m < 0 else f"{m}/{r.get('total')}", r.get("label") or ""])
    console.table(rows, ["ITEM", "DETECTIONS", "LABEL"])
    return 2 if worst >= 3 else 0


def cmd_sample(a) -> int:
    """``droidtriage sample``: write synthetic evidence (see :mod:`sample`)."""
    from .sample import build
    build(a.out, a.apk)
    console.info(f"wrote {a.out} – now run: droidtriage analyze {a.out}")
    return 0


def cmd_rules(a) -> int:
    """``droidtriage rules``: analysers, logcat rules, APK code rules, trackers, packers, playbook."""
    from . import apk, logs, pipeline  # noqa: F401
    from .playbook import PLAYBOOK
    from .registry import ordered
    data = {
        "analyzers": [{"name": x.name, "order": x.order, "title": x.title, "description": x.description} for x in ordered()],
        "logcat_rules": [{"id": "log." + r.id, "severity": r.severity, "category": r.category, "title": r.title, "mitre": r.mitre} for r in logs.RULES],
        "apk_code_rules": [{"id": "apk." + r[0], "severity": r[2], "category": r[3], "title": r[4], "mitre": r[5]} for r in apk.API_RULES],
        "trackers": sorted(set(apk.TRACKERS.values())),
        "packers": sorted(set(apk.PACKER_LIBS.values()) | set(apk.PACKER_CLASSES.values())),
        "playbook_prefixes": [p for p, _ in PLAYBOOK],
    }
    if a.json:
        json.dump(data, sys.stdout, indent=1)
        print()
        return 0
    console.table([[x["order"], x["name"], x["title"], x["description"]] for x in data["analyzers"]], ["ORDER", "ANALYSER", "TITLE", "WHAT"])
    for key, title in (("logcat_rules", "LOGCAT RULES"), ("apk_code_rules", "APK CODE RULES")):
        print()
        console.table([[console.c(r["severity"], r["severity"]), r["id"], r["title"], r["mitre"] or ""] for r in data[key]], ["SEV", title, "", "ATT&CK"])
    print(f"\n{len(data['trackers'])} tracker SDKs, {len(data['packers'])} packers, {len(data['playbook_prefixes'])} playbook entries")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns the process exit code."""
    argv = _normalise_argv(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    a = parser.parse_args(argv)
    console.configure(quiet=getattr(a, "quiet", False), verbose=getattr(a, "verbose", False),
                      color=False if getattr(a, "no_color", False) else None)
    if not a.command:
        parser.print_help()
        return 3
    handler = {"analyze": cmd_analyze, "apk": cmd_apk, "diff": cmd_diff, "iocs": cmd_iocs, "vt": cmd_vt,
               "sample": cmd_sample, "rules": cmd_rules}[a.command]
    try:
        return handler(a)
    except KeyboardInterrupt:
        console.error("interrupted")
        return 130

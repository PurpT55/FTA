import unittest

from droidtriage import logs, network, packages
from droidtriage.network import classify

from .helpers import app, ctx_for, ids, iocs

L = "10-20 22:01:0{n}.123 {uid}  4242  4250 I {tag}: {msg}"
LINES = [
    ("u0_a250", "Magisk", "su: request granted for uid 10250"),
    ("system", "ClipboardService", "Denying clipboard access to com.spy, application is not in focus"),
    ("u0_a99", "frida", "gum-js-loop started"),
    ("system", "DevicePolicyManager", "setActiveAdmin com.spy/.Admin"),
    ("u0_a250", "okhttp", "--> POST https://copy9.com/api/upload"),
    ("u0_a10", "AndroidRuntime", "FATAL EXCEPTION: main"),
    ("u0_a11", "auditd", "avc: denied { read } for name=x"),
    ("system", "KeyChain", "installed CA certificate user:abcd"),
] + [("system", "ActivityManager", f"Start proc 900{i}:com.spy/u0a250 for service {{com.spy/com.spy.Up}}") for i in range(6)]


def logfile():
    return "\n".join(L.format(n=i % 10, uid=u, tag=t, msg=m) for i, (u, t, m) in enumerate(LINES)) + "\n"


class LogRules(unittest.TestCase):
    def setUp(self):
        self.ctx = ctx_for({"logs/logcat_main.txt": logfile(),
                            "packages/packages.json": [app("com.spy", installer=None, launcher=False)]})
        packages.load_packages(self.ctx)
        logs.analyse_logs(self.ctx)

    def test_hits(self):
        hits = self.ctx.log_hits
        for rid in ("root.su", "clipboard.bg", "frida", "admin.add", "fatal", "selinux.denied", "cert.install"):
            self.assertIn(rid, hits)
        self.assertEqual(hits["clipboard.bg"]["packages"], {"com.spy": 1})
        got = ids(self.ctx)
        self.assertTrue({"log.root.su", "log.frida", "log.ioc.domain", "log.bgstart"} <= got, got)
        self.assertNotIn("log.fatal", got)                    # INFO rules feed the report only
        self.assertEqual(self.ctx.network["log_domains"]["copy9.com"], 1)
        self.assertTrue(self.ctx.coverage["logcat"].startswith("ok"))

    def test_timeline_years(self):
        ts = {e.ts[:4] for e in self.ctx.timeline if e.source.startswith("logcat")}
        self.assertTrue(ts and all(t.isdigit() for t in ts))

    def test_rule_table_is_consistent(self):
        seen = set()
        for r in logs.RULES:
            self.assertNotIn(r.id, seen)
            seen.add(r.id)
            self.assertTrue(r.tag or r.keys, f"{r.id} needs keys")
            self.assertTrue(all(k == k.lower() for k in r.keys), r.id)

    def test_limited_coverage_when_read_logs_missing(self):
        ctx = ctx_for({"logs/logcat_main.txt": logfile(), "manifest.json": {"capabilities": {"READ_LOGS": False}}})
        logs.analyse_logs(ctx)
        self.assertTrue(ctx.coverage["logcat"].startswith("LIMITED"))


class Network(unittest.TestCase):
    def test_classify(self):
        db = iocs()
        cases = {
            ("copy9.com", "x"): "IOC:TheTruthSpy",
            ("abc.duckdns.org", "x"): "dynamic-dns",
            ("x.ngrok-free.app", "x"): "tunnel-service",
            ("api.telegram.org", "com.spy"): "telegram-bot-api",
            ("api.telegram.org", "org.telegram.messenger"): None,
            ("xk2j9qpzvbnw.top", "x"): "dga-like",
            ("shop.example.xyz", "x"): "risky-tld",
            ("app-measurement.com", "x"): "tracker",
            ("connectivitycheck.gstatic.com", "x"): None,
        }
        for (d, p), want in cases.items():
            self.assertEqual(classify(d, p, db), want, d)

    def test_sentinel_and_volume(self):
        ctx = ctx_for({
            "packages/packages.json": [app("com.spy", installer=None, launcher=False), app("com.whatsapp")],
            "sentinel/report.json": {"monitor": {"dns": [{"package": "com.spy", "domain": d} for d in ("copy9.com", "api.telegram.org")],
                                                 "events": [{"ts": 1792590875000, "severity": "HIGH", "type": "net.bgupload",
                                                             "title": "Large upload", "package": "com.spy", "category": "SUSPICIOUS"}],
                                                 "virustotal": []}},
            "usage/netstats_uid.tsv": "network\tuid\tpackages\tstart\tend\trxBytes\ttxBytes\tstate\n"
                                      "wifi\t1\tcom.spy\ta\tb\t10\t52428800\t-1\nwifi\t2\tcom.whatsapp\ta\tb\t10\t52428800\t-1\n",
            "usage/usage_daily.tsv": "day\tpackage\tforegroundMs\tlastUsed\nd\tcom.whatsapp\t100\tx\n",
        })
        packages.load_packages(ctx)
        network.analyse_network(ctx)
        got = ids(ctx, "com.spy")
        self.assertTrue({"dns.ioc", "dns.telegram-bot-api", "sentinel.net.bgupload", "net.unused.tx"} <= got, got)
        self.assertEqual(ids(ctx, "com.whatsapp"), set())
        self.assertEqual(ctx.timeline[0].ts, "2026-10-21 13:54:35")


if __name__ == "__main__":
    unittest.main()

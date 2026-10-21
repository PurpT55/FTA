import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from droidtriage import cli, vt
from droidtriage.baseline import diff_reports
from droidtriage.registry import ordered
from droidtriage.sample import build

from .helpers import ECHAP_SNIPPET, app, ctx_for


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _load(path):
    return json.loads(_read(path))


def run_cli(*argv):
    """Run the CLI in-process; returns (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class VirusTotalClient(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.patches = [mock.patch.object(vt, "CACHE", os.path.join(self.tmp, "c.json")), mock.patch.object(vt, "SPACING", 0)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_lookup_cache(self):
        calls = []

        def fake(url, data=None, headers=None):
            calls.append(url)
            if url.endswith("/files/aa"):
                return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "undetected": 60},
                                                     "popular_threat_classification": {"suggested_threat_label": "trojan.spy"}}}}
            return 404, {}
        c = vt.VirusTotal("k")
        c._req = fake
        self.assertEqual(c.lookup("aa")["malicious"], 5)
        self.assertEqual(c.lookup("bb")["malicious"], -1)
        self.assertEqual(c.lookup("aa")["label"], "trojan.spy")
        self.assertEqual(len(calls), 2)                        # third call served from cache
        c2 = vt.VirusTotal("k")                                # cache persisted to disk
        self.assertIn("aa", c2.cache)

    def test_quota_raises(self):
        c = vt.VirusTotal("k")
        c._req = lambda *a, **k: (429, {})
        with self.assertRaises(RuntimeError):
            c.lookup("cc")

    def test_upload_needs_confirmation(self):
        with redirect_stdout(io.StringIO()), mock.patch("sys.stdin.isatty", return_value=False):
            self.assertFalse(vt.confirm_upload("x", False))
            self.assertTrue(vt.confirm_upload("x", True))

    def test_analyser_without_key_reuses_sentinel(self):
        ctx = ctx_for({"sentinel/report.json": {"monitor": {"virustotal": [{"sha256": "ab", "positives": 4, "total": 70}]}}})
        vt.run_vt(ctx)
        self.assertEqual(ctx.vt["ab"]["malicious"], 4)
        self.assertIn("skipped", ctx.coverage["virustotal"])


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.iocs = os.path.join(cls.tmp, "ioc.yaml")
        with open(cls.iocs, "w") as fh:
            fh.write(ECHAP_SNIPPET)
        cls.sample = build(os.path.join(cls.tmp, "sample.zip"))
        cls.out = os.path.join(cls.tmp, "report")
        cls.code, cls.stdout, cls.stderr = run_cli("analyze", cls.sample, "-o", cls.out, "--ioc", cls.iocs,
                                                    "--no-default-iocs", "--json", "-q", "-j", "1")

    def test_exit_code_and_outputs(self):
        self.assertEqual(self.code, 2)                           # malware indicators planted
        for f in ("report.html", "report.json", "findings.csv", "apps.csv", "timeline.csv"):
            self.assertTrue(os.path.exists(os.path.join(self.out, f)), f)
        data = json.loads(self.stdout)
        self.assertGreaterEqual(len(data["summary"]["malware"]), 2)
        report = _load(os.path.join(self.out, "report.json"))
        self.assertEqual(report["schemaVersion"], 2)
        self.assertEqual(set(report["timings"]), {a.name for a in ordered()})

    def test_planted_indicators_found(self):
        report = _load(os.path.join(self.out, "report.json"))
        got = {(f["id"], f["package"]) for f in report["findings"]}
        for expected in [("ioc.package", "com.systemservice"), ("cert.platform", "com.evil.platform"),
                         ("task.hijack", "com.google.android.update.service"), ("appops.bg", "com.systemservice"),
                         ("dns.telegram-bot-api", "com.systemservice"), ("log.ioc.domain", None),
                         ("net.unused.tx", "com.systemservice"), ("dev.userca", None)]:
            self.assertIn(expected, got)

    def test_html_is_self_contained(self):
        html = _read(os.path.join(self.out, "report.html"))
        self.assertNotIn("__DATA__", html)
        self.assertEqual(html.count("</script>"), 2)           # embedded JSON cannot close the tag early

    def test_fail_on_and_formats(self):
        out = os.path.join(self.tmp, "r2")
        code, _, _ = run_cli("analyze", self.sample, "-o", out, "--no-default-iocs", "-q", "--fail-on", "never", "-f", "json")
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(out)), ["report.json"])

    def test_bad_arguments(self):
        self.assertEqual(run_cli("analyze", self.sample, "--skip", "nope", "-q")[0], 3)
        self.assertEqual(run_cli("analyze", self.sample, "-f", "pdf", "-q")[0], 3)
        self.assertEqual(run_cli("analyze", "/does/not/exist", "-q")[0], 3)

    def test_legacy_invocation(self):
        self.assertEqual(cli._normalise_argv([self.sample, "-o", "x"]), ["analyze", self.sample, "-o", "x"])
        self.assertEqual(cli._normalise_argv(["--update-iocs"]), ["iocs", "update"])
        self.assertEqual(cli._normalise_argv(["rules"]), ["rules"])

    def test_baseline_and_diff(self):
        extra = os.path.join(self.tmp, "extra.txt")
        with open(extra, "w") as fh:
            fh.write("package:com.whatsapp\n")                       # one more indicator -> exactly one NEW finding family
        out2 = os.path.join(self.tmp, "r3")
        run_cli("analyze", self.sample, "-o", out2, "--ioc", self.iocs, "--ioc", extra, "--no-default-iocs", "-q",
                "--baseline", os.path.join(self.out, "report.json"))
        r = _load(os.path.join(out2, "report.json"))
        new = {(f["id"], f["package"]) for f in r["findings"] if f["new"]}
        self.assertIn(("ioc.package", "com.whatsapp"), new)
        self.assertNotIn(("ioc.package", "com.systemservice"), new)
        code, stdout, _ = run_cli("diff", os.path.join(self.out, "report.json"), os.path.join(out2, "report.json"), "--json")
        d = json.loads(stdout)
        self.assertEqual(code, 0)
        self.assertEqual(d["apps_added"], [])
        self.assertIn("com.whatsapp", {f["package"] for f in d["findings_new"]})
        self.assertEqual(d["findings_gone"], [])

    def test_skip_analyser(self):
        out = os.path.join(self.tmp, "r4")
        run_cli("analyze", self.sample, "-o", out, "--no-default-iocs", "-q", "--skip", "logcat,network", "-f", "json")
        r = _load(os.path.join(out, "report.json"))
        self.assertEqual(r["coverage"]["logcat"], "skipped (--skip)")
        self.assertFalse(any(f["source"] == "logcat" for f in r["findings"]))


class OtherCommands(unittest.TestCase):
    def test_rules_json(self):
        code, out, _ = run_cli("rules", "--json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual([a["name"] for a in data["analyzers"]],
                         ["inventory", "apk", "virustotal", "device", "dumpsys", "packages", "logcat", "network"])
        self.assertGreater(len(data["logcat_rules"]), 20)

    def test_iocs_check(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "x.yaml")
        with open(p, "w") as fh:
            fh.write(ECHAP_SNIPPET)
        with mock.patch.dict(os.environ, {"DROIDTRIAGE_IOCS": d}):
            self.assertEqual(run_cli("iocs", "check", "com.systemservice", "www.copy9.com")[0], 2)
            code, out, _ = run_cli("iocs", "check", "com.whatsapp")
            self.assertEqual(code, 0)
            self.assertIn("no match", out)
            self.assertIn("TheTruthSpy", run_cli("iocs", "stats")[1] + "TheTruthSpy")

    def test_vt_requires_key(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VT_API_KEY", None)
            self.assertEqual(run_cli("vt", "lookup", "aa", "--vt-key", "")[0], 3)

    def test_help_lists_commands(self):
        with self.assertRaises(SystemExit):
            run_cli("--help")
        code, _, _ = run_cli()
        self.assertEqual(code, 3)

    def test_baseline_diff_pure(self):
        old = {"apps": [{"package": "a", "version": "1"}], "findings": [{"id": "x", "package": "a", "title": "t"}], "summary": {}}
        new = {"apps": [{"package": "a", "version": "2"}, {"package": "b"}], "findings": [], "summary": {}}
        d = diff_reports(old, new)
        self.assertEqual(d["apps_added"], ["b"])
        self.assertEqual(d["apps_changed"][0]["changes"]["version"], ("1", "2"))
        self.assertEqual(len(d["findings_gone"]), 1)


class Scores(unittest.TestCase):
    def test_summary_definitions(self):
        from droidtriage.console import console
        from droidtriage.pipeline import run_all
        from droidtriage.report import summary
        console.configure(quiet=True)
        ctx = run_all(ctx_for({"packages/packages.json": [app("com.x", installer=None)]}))
        s = summary(ctx)
        self.assertEqual(s["unknownBinaries"], ["com.x"])            # sideloaded + unknown to VT
        self.assertEqual(s["malware"], [])
        self.assertEqual(s["securityRisk"], 0)                       # install.untrusted is UNKNOWN, not SECURITY


if __name__ == "__main__":
    unittest.main()

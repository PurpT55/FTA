"""APK analysis tests.

The rule layer is tested with plain strings / dicts. The binary parsers (manifest, DEX, signing
blocks) are exercised against a real APK when DROIDTRIAGE_TEST_APK points to one, e.g.::

    curl -LO https://github.com/emanuele-f/PCAPdroid/releases/download/v1.7.2/PCAPdroid_v1.7.2.apk
    DROIDTRIAGE_TEST_APK=PCAPdroid_v1.7.2.apk python3 -m unittest tests.test_apk
"""
import os
import unittest

from droidtriage import apk


class CodeRules(unittest.TestCase):
    def test_code_findings(self):
        strings = ["Ldalvik/system/InMemoryDexClassLoader;", "sendTextMessage", "https://api.telegram.org/bot123/sendMessage",
                   "Lcom/appsflyer/AppsFlyerLib;", "http://45.67.89.10:8080/gate.php", "https://www.w3.org/2000/svg",
                   "http://www.css", "Ljava/lang/Runtime;", "exec", "result"]
        found, ext = apk.code_findings(strings)
        got = {f["id"] for f in found}
        self.assertTrue({"apk.dcl.mem", "apk.sms.send", "apk.c2.telegram", "apk.http.ip"} <= got, got)
        self.assertNotIn("apk.exec.su", got)                       # "su" must be an exact DEX string
        self.assertEqual(ext["trackers"], ["AppsFlyer"])
        self.assertIn("api.telegram.org", ext["hosts"])
        self.assertNotIn("www.w3.org", ext["hosts"])
        self.assertNotIn("www.css", ext["hosts"])                  # not a real TLD
        self.assertIn("45.67.89.10", ext["ips"])
        found2, _ = apk.code_findings(strings + ["su"])
        self.assertIn("apk.exec.su", {f["id"] for f in found2})

    def test_manifest_findings(self):
        m = {"application": {"debuggable": True}, "components": [
            {"name": "r.Sms", "filters": [{"actions": ["android.provider.Telephony.SMS_RECEIVED"], "priority": 2147483647}]},
            {"name": "r.Boot", "filters": [{"actions": ["android.intent.action.BOOT_COMPLETED"], "priority": 0}]},
            {"name": "r.Code", "filters": [{"actions": ["android.provider.Telephony.SECRET_CODE"]}]},
        ]}
        got = {f["id"] for f in apk.manifest_findings(m)}
        self.assertEqual(got, {"apk.sms.intercept", "apk.boot", "apk.secret.code", "apk.debuggable"})
        self.assertEqual(apk.manifest_findings({}), [])

    def test_entropy_and_bad_input(self):
        self.assertEqual(apk.entropy(b""), 0.0)
        self.assertAlmostEqual(apk.entropy(bytes(range(256)) * 4), 8.0)
        rep = apk.analyse_apk(b"not an apk", "x")
        self.assertTrue(rep["errors"])
        self.assertEqual(apk.dex_strings(b"nope"), [])

    def test_rule_tables(self):
        ids = [r[0] for r in apk.API_RULES]
        self.assertEqual(len(ids), len(set(ids)))
        for r in apk.API_RULES:
            self.assertIn(r[2], ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"))


@unittest.skipUnless(os.environ.get("DROIDTRIAGE_TEST_APK"), "set DROIDTRIAGE_TEST_APK to a real APK")
class RealApk(unittest.TestCase):
    def test_parsers(self):
        with open(os.environ["DROIDTRIAGE_TEST_APK"], "rb") as fh:
            rep = apk.analyse_apk(fh.read(), "real")
        m = rep["manifest"]
        self.assertTrue(m["package"])
        self.assertTrue(m["permissions"])
        self.assertTrue(m["components"])
        self.assertTrue(rep["certs"], "no signer extracted")
        self.assertEqual(len(rep["certs"][0]["sha256"]), 64)
        self.assertGreater(rep["dex_count"], 0)
        self.assertFalse(rep["errors"])

    def test_parallel_equals_serial(self):
        from droidtriage import apkscan
        from droidtriage.console import console
        from .helpers import ctx_for
        console.configure(quiet=True)
        with open(os.environ["DROIDTRIAGE_TEST_APK"], "rb") as fh:
            data = fh.read()
        files = {f"apks/com.copy{i}/base.apk": data for i in range(4)}
        results = []
        for jobs in (1, 2):
            ctx = ctx_for(files, jobs=jobs)
            apkscan.analyse_apks(ctx)
            results.append(sorted((f.id, f.package) for f in ctx.findings))
            self.assertEqual(len(ctx.apk_reports), 4)
        self.assertEqual(results[0], results[1])


if __name__ == "__main__":
    unittest.main()

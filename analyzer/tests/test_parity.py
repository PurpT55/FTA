"""Kotlin (on-device) and Python (offline) rules must speak the same finding ids, so reports from
DroidSentinel and droidtriage can be compared and the playbook applies to both."""
import glob
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
KOTLIN_RULES = os.path.join(ROOT, "android", "core", "src", "main", "java", "org", "droidsuite", "core")
PY = os.path.join(ROOT, "analyzer", "droidtriage")


def ids(pattern, files):
    out = set()
    for f in files:
        with open(f, encoding="utf-8") as fh:
            out |= set(re.findall(pattern, fh.read()))
    return out


@unittest.skipUnless(os.path.isdir(KOTLIN_RULES), "android sources not present")
class Parity(unittest.TestCase):
    def test_every_on_device_rule_exists_offline(self):
        kt = ids(r'Finding\("([\w.]+)"', glob.glob(os.path.join(KOTLIN_RULES, "*Rules.kt")))
        py = ids(r'(?:Finding|add)\("([\w.\-]+)"', glob.glob(os.path.join(PY, "*.py")))
        self.assertGreater(len(kt), 30)
        self.assertEqual(kt - py, set(), "add these ids to the Python analyzer (or document why not)")

    def test_domain_heuristic_thresholds_match(self):
        with open(os.path.join(ROOT, "android", "sentinel", "src", "main", "java", "org", "droidsuite", "sentinel", "DomainIntel.kt")) as fh:
            kt = fh.read()
        with open(os.path.join(PY, "network.py")) as fh:
            py = fh.read()
        self.assertEqual(re.search(r"entropy\(label\) > ([\d.]+)", kt).group(1), re.search(r"_entropy\(label\) > ([\d.]+)", py).group(1))
        for d in ("duckdns.org", "ngrok-free.app", "trycloudflare.com", "pastebin.com", "app-measurement.com"):
            self.assertIn(f'"{d}"', kt)
            self.assertIn(f'"{d}"', py)


if __name__ == "__main__":
    unittest.main()

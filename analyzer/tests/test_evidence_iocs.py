import json
import os
import tempfile
import unittest
import zipfile

from droidtriage.evidence import Evidence
from droidtriage.iocs import IocDb

from .helpers import ECHAP_SNIPPET, evidence_dir


class EvidenceTest(unittest.TestCase):
    def test_zip_with_wrapping_folder(self):
        path = os.path.join(tempfile.mkdtemp(), "e.zip")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("dump/manifest.json", json.dumps({"tool": "x"}))
            z.writestr("dump/logs/logcat_main.txt", "a\nb\n")
        ev = Evidence(path)
        self.assertTrue(ev.has("manifest.json"))
        self.assertEqual(ev.json("manifest.json")["tool"], "x")
        self.assertEqual(list(ev.lines("logs/logcat_main.txt")), ["a", "b"])
        self.assertEqual(ev.names("logs/*.txt"), ["logs/logcat_main.txt"])

    def test_dir_and_defaults(self):
        ev = Evidence(evidence_dir({"device/getprop.txt": "[a]: [b]\n", "bad.json": "{"}))
        self.assertEqual(ev.text("missing.txt", "dflt"), "dflt")
        self.assertIsNone(ev.json("bad.json"))
        self.assertEqual(ev.first("nope", "device/getprop.txt"), "device/getprop.txt")

    def test_rejects_other_files(self):
        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(b"not a zip")
        f.close()
        with self.assertRaises(ValueError):
            Evidence(f.name)


class IocTest(unittest.TestCase):
    def test_echap_yaml(self):
        db = IocDb()
        db._yaml(ECHAP_SNIPPET, "src")
        self.assertEqual(db.packages["com.systemservice"], "TheTruthSpy")
        self.assertIn("31a6ececd97cf39bc4126b8745cd94a7c30bf81c", db.cert_sha1)
        self.assertIn("69.64.74.239", db.ips)
        self.assertEqual(db.match_domain("x.api.thetruth.example"), "TheTruthSpy")
        self.assertEqual(db.match_domain("www.copy9.com."), "TheTruthSpy")
        self.assertIsNone(db.match_domain("copy9.com.evil.org"))

    def test_stix2_and_text(self):
        bundle = {"type": "bundle", "objects": [
            {"type": "malware", "id": "malware--1", "name": "Pegasus"},
            {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value = 'bad.example']"},
            {"type": "indicator", "id": "indicator--2", "pattern": "[app:id = 'com.bad.app']"},
            {"type": "indicator", "id": "indicator--3", "pattern": "[file:hashes.sha256 = 'AB12']"},
            {"type": "relationship", "relationship_type": "indicates", "source_ref": "indicator--1", "target_ref": "malware--1"},
        ]}
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "p.stix2"), "w") as fh:
            json.dump(bundle, fh)
        with open(os.path.join(d, "mine.txt"), "w") as fh:
            fh.write("# comment\npackage:com.mine\ndomain:Evil.Example\nsha256:FF\n")
        with open(os.path.join(d, "README.md"), "w") as fh:
            fh.write("package:ignored")
        db = IocDb()
        db.load_path(d)
        self.assertEqual(db.domains["bad.example"], "Pegasus")
        self.assertIn("com.bad.app", db.packages)
        self.assertIn("ab12", db.hashes)
        self.assertEqual(db.packages["com.mine"], "mine")
        self.assertIn("evil.example", db.domains)
        self.assertNotIn("ignored", db.packages)
        self.assertEqual(len(db.sources), 2)


if __name__ == "__main__":
    unittest.main()

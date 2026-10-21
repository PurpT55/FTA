"""Timestamp normalisation, Finding validation, de-duplication order."""
import unittest
from datetime import datetime

from droidtriage.model import Finding, norm_ts, sev_rank

from .helpers import ctx_for


class NormTs(unittest.TestCase):
    REF = datetime(2026, 10, 21, 12, 0, 0)

    def test_formats(self):
        self.assertEqual(norm_ts("2026-10-16T13:52:47Z"), "2026-10-16 13:52:47")
        self.assertEqual(norm_ts("2025-10-20 23:05:00.000"), "2025-10-20 23:05:00")
        self.assertEqual(norm_ts(1792590875000), "2026-10-21 13:54:35")
        self.assertEqual(norm_ts("1792590875"), "2026-10-21 13:54:35")
        self.assertEqual(norm_ts("weird"), "weird")
        self.assertEqual(norm_ts(None), "")

    def test_logcat_year_inference(self):
        self.assertEqual(norm_ts("10-20 22:01:02.123", self.REF), "2026-10-20 22:01:02")
        # December entries collected in October belong to the previous year
        self.assertEqual(norm_ts("12-31 23:59:59.000", self.REF), "2025-12-31 23:59:59")


class FindingModel(unittest.TestCase):
    def test_validation(self):
        with self.assertRaises(ValueError):
            Finding("x", "SEVERE", "SECURITY", "t")
        with self.assertRaises(ValueError):
            Finding("x", "HIGH", "NOPE", "t")

    def test_dedupe_and_order(self):
        ctx = ctx_for({})
        ctx.add(Finding("a", "LOW", "SECURITY", "low"))
        ctx.add(Finding("b", "CRITICAL", "MALWARE", "crit"))
        ctx.add(Finding("a", "LOW", "SECURITY", "low"))
        ctx.dedupe()
        self.assertEqual([f.id for f in ctx.findings], ["b", "a"])
        self.assertGreater(sev_rank("CRITICAL"), sev_rank("HIGH"))


if __name__ == "__main__":
    unittest.main()

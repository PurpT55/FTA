---
name: fta-add-detection-rule
description: Add or change a detection in this repo (Python droidtriage analyser/rule, Kotlin DroidSentinel AppRule/DeviceRule, logcat rule, APK code or manifest rule, IOC format, playbook advice) while keeping ids, tests, parity and the project index consistent. Use for any "detect X", "flag Y", "new rule", "new analyser" or false-positive tuning request.
---

# Adding a detection

## Pick the layer
| Evidence | Python (offline) | Kotlin (on device) |
|---|---|---|
| package metadata, permissions, roles | `analyzer/droidtriage/packages.py` → `analyse_packages` | `android/core/.../AppRules.kt` → new `AppRule`, add to `ALL` |
| device props/settings | `system.py` → `analyse_device` | `DeviceRules.kt` → new `DeviceRule`, add to `ALL` |
| dumpsys output | `system.py` → `analyse_dumpsys` (+ helper parser) | n/a (apps can't run dumpsys) |
| logcat line | `logs.py` → append a `LogRule` to `RULES` | n/a |
| DEX strings in an APK | `apk.py` → `API_RULES` tuple (`"=x"` = exact string) | n/a |
| manifest intent filters | `apk.py` → `MANIFEST_RULES` | n/a |
| DNS name | `network.py` `classify` | `sentinel/.../DomainIntel.kt` (**keep both lists identical**) |
| new evidence source | new module with `@analyzer(name, order, title)` + import it in `pipeline.py` | n/a |

## Conventions (enforced by tests)
- **Finding id** = `family.rule`, lowercase, stable (used for dedupe, baseline diff, the playbook and parity).
  Device-level ids start with `dev.`, logcat ids get the `log.` prefix automatically, APK ids get `apk.`.
- **Severity rubric**: CRITICAL = confirmed compromise (IOC, platform key, VT ≥3). HIGH = abusable access or
  tampering that needs action. MEDIUM = suspicious, needs review. LOW = hygiene. INFO = context only (not
  counted in scores). **Category**: one of PRIVACY, SECURITY, SUSPICIOUS, UNKNOWN, MALWARE. Only SECURITY and
  MALWARE feed the security score.
- **Demote capability findings for store/system apps** (see `apkscan._merge`): code that *can* read SMS is normal
  in a messenger and alarming in a sideloaded "System Service".
- **MITRE**: ATT&CK *Mobile* technique ids only (e.g. T1417.002). If unsure, leave `None` rather than guess.
  Add new ids to the table in `docs/RISK_MATRIX.md` §4.
- **Logcat rules without a tag regex must define `keys`** (lowercase literals). That's the fast pre-filter;
  `test_rule_table_is_consistent` fails otherwise. Tag regexes must be literal alternations (`A|B|C`).
- **Parity**: every id in `AppRules.kt`/`DeviceRules.kt` must exist in Python (`tests/test_parity.py`).
- **Advice**: add a `(prefix, text)` to `playbook.py` if the remediation is new. The longest-matching prefix
  isn't used; the first match wins, so put specific prefixes before general ones.

## Checklist
1. Implement (see table).
2. Test with plain fixtures, never with fabricated binaries: Python in `analyzer/tests/test_*.py` using
   `helpers.ctx_for({...files...})` + `ids(ctx, pkg)`; Kotlin in `core/src/test/.../RiskEngineTest.kt` using `Fixtures.app()`.
   Add a negative case too (a store app that must stay quiet).
3. If the sample should demonstrate it, add a planted record/line in `droidtriage/sample.py` and an assertion in
   `test_vt_report_cli.EndToEnd.test_planted_indicators_found`.
4. Run: `cd analyzer && python3 -W error::ResourceWarning -m unittest discover -s tests -t .` and `tools/kotlin_check.sh`.
5. Update docs if user-visible (`docs/GUIDE.md` §5.3 table, `docs/RISK_MATRIX.md`).
6. `python3 tools/gen_index.py` (CI fails on a stale index).

import unittest

from droidtriage import packages, system
from droidtriage.packages import parse_dumpsys_package

from .helpers import app, ctx_for, ids

P = "android.permission."
DUMPSYS_PACKAGE = """Packages:
  Package [com.spy.hidden] (abc123):
    userId=10250
    codePath=/data/app/~~x==/com.spy.hidden-y==
    versionCode=7 minSdk=21 targetSdk=22
    versionName=2.1
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
    firstInstallTime=2026-10-15 10:00:01
    lastUpdateTime=2026-10-15 10:00:01
    installerPackageName=null
    requested permissions:
      android.permission.READ_SMS
      android.permission.SEND_SMS
      android.permission.RECORD_AUDIO
    install permissions:
      android.permission.READ_SMS: granted=true
      android.permission.SEND_SMS: granted=true
    User 0: ceDataInode=1 installed=true hidden=false
      runtime permissions:
        android.permission.RECORD_AUDIO: granted=true, flags=[ USER_SET ]
        android.permission.READ_CALL_LOG: granted=false
  Package [com.android.settings] (aaa):
    userId=1000
    versionCode=34 minSdk=34 targetSdk=34
    flags=[ SYSTEM HAS_CODE PERSISTENT ]
    installerPackageName=null

Hidden system packages:
  Package [com.android.bogus] (zzz):
    userId=1
"""


class DumpsysPackage(unittest.TestCase):
    def test_parse(self):
        p = parse_dumpsys_package(DUMPSYS_PACKAGE)
        self.assertEqual(set(p), {"com.spy.hidden", "com.android.settings"})
        spy = p["com.spy.hidden"]
        self.assertEqual((spy["uid"], spy["versionCode"], spy["targetSdk"], spy["installer"]), (10250, 7, 22, None))
        self.assertEqual(spy["granted"], {P + "READ_SMS", P + "SEND_SMS", P + "RECORD_AUDIO"})
        self.assertEqual(spy["requested"], [P + "READ_SMS", P + "SEND_SMS", P + "RECORD_AUDIO"])
        self.assertTrue(p["com.android.settings"]["system"])
        self.assertFalse(spy["system"])

    def test_adb_layout_end_to_end(self):
        ctx = ctx_for({"dumpsys/package.txt": DUMPSYS_PACKAGE,
                       "packages/pm_list.txt": "package:/data/app/x/base.apk=com.spy.hidden  installer=null uid:10250\n",
                       "packages/launcher_activities.txt": "com.android.settings/.Settings\n"})
        packages.load_packages(ctx)
        self.assertFalse(ctx.packages["com.spy.hidden"]["hasLauncher"])
        packages.analyse_packages(ctx)
        got = ids(ctx, "com.spy.hidden")
        self.assertTrue({"sms.full", "hidden", "sdk.old", "install.untrusted"} <= got, got)
        self.assertIn("partial", ctx.coverage["inventory"])


class PackageRules(unittest.TestCase):
    def run_rules(self, apps, device_state=None, **files):
        f = {"packages/packages.json": apps, "device/device_state.json": device_state or {}}
        f.update(files)
        ctx = ctx_for(f)
        packages.load_packages(ctx)
        system.analyse_device(ctx)
        packages.analyse_packages(ctx)
        return ctx

    def test_ioc_and_hidden_spyware(self):
        spy = app("com.systemservice", "System Service", installer=None, launcher=False,
                  granted=[P + x for x in ("ACCESS_FINE_LOCATION", "RECORD_AUDIO", "READ_SMS", "SEND_SMS", "READ_CALL_LOG", "READ_CONTACTS")])
        ctx = self.run_rules([spy], {"enabledAccessibility": ["com.systemservice/.Acc"], "activeAdmins": ["com.systemservice/.Adm"],
                                     "overlayGranted": ["com.systemservice"]})
        got = ids(ctx, "com.systemservice")
        for expected in ("ioc.package", "acc.enabled", "admin.active", "overlay.acc", "sms.full", "hidden", "stalkerware.profile", "mask.name"):
            self.assertIn(expected, got)

    def test_platform_key_masquerade_and_strandhogg(self):
        apps = [
            app("android", "Android System", installer=None, system=True, cert="pp"),
            app("com.whatsapp", "WhatsApp"),
            app("com.evil.platform", "Battery", installer=None, cert="pp"),
            app("com.google.android.update", "WhatsApp", installer=None,
                components=[{"type": "activity", "name": "x.Login", "taskAffinity": "com.whatsapp"}]),
        ]
        ctx = self.run_rules(apps)
        self.assertIn("cert.platform", ids(ctx, "com.evil.platform"))
        got = ids(ctx, "com.google.android.update")
        self.assertTrue({"task.hijack", "mask.label", "mask.pkg"} <= got, got)
        self.assertNotIn("install.untrusted", ids(ctx, "com.whatsapp"))

    def test_store_app_is_quiet(self):
        ctx = self.run_rules([app("com.whatsapp", "WhatsApp", granted=[P + "CAMERA", P + "RECORD_AUDIO"])])
        self.assertEqual(ids(ctx, "com.whatsapp"), set())
        s = packages.scores(ctx)["com.whatsapp"]
        self.assertEqual(s["privacy"], 18)
        self.assertEqual(s["security"], 0)

    def test_install_cluster(self):
        apps = [app(f"com.side{i}", installer=None, first=f"2026-10-16T13:5{i}:00Z") for i in range(3)]
        ctx = self.run_rules(apps)
        self.assertIn("install.cluster", ids(ctx, None))


class DevicePosture(unittest.TestCase):
    def test_props_and_settings(self):
        ctx = ctx_for({
            "device/getprop.txt": "[ro.boot.verifiedbootstate]: [orange]\n[ro.boot.flash.locked]: [0]\n"
                                  "[ro.build.tags]: [test-keys]\n[ro.build.version.security_patch]: [2020-01-05]\n[ro.build.version.sdk]: [29]\n",
            "device/settings_global.txt": "adb_wifi_enabled=1\npackage_verifier_enable=0\nhttp_proxy=10.0.0.1:8080\n",
            "device/settings_secure.txt": "enabled_accessibility_services=com.x/.A:com.y/.B\n",
            "device/data_local_tmp.txt": "-rwxr-xr-x 1 shell shell 1000 2026-10-01 10:00 exploit\n",
        })
        system.analyse_device(ctx)
        got = ids(ctx, None)
        for expected in ("dev.vb", "dev.unlocked", "dev.testkeys", "dev.patch", "dev.eol", "dev.adbwifi", "dev.verifier", "dev.proxy", "dev.localtmp"):
            self.assertIn(expected, got)
        self.assertEqual(ctx.enabled["accessibility"], {"com.x/.A", "com.y/.B"})

    def test_clean_device(self):
        ctx = ctx_for({"device/getprop.txt": "[ro.boot.verifiedbootstate]: [green]\n[ro.boot.flash.locked]: [1]\n"
                                             "[ro.build.tags]: [release-keys]\n[ro.build.version.sdk]: [35]\n",
                       "device/device_state.json": {"screenLockSecure": True}})
        system.analyse_device(ctx)
        self.assertEqual(ids(ctx, None), set())


class Dumpsys(unittest.TestCase):
    def test_roles_owner_appops_jobs(self):
        ctx = ctx_for({
            "packages/packages.json": [app("com.spy", installer=None), app("com.android.vending", system=True, installer=None)],
            "dumpsys/accessibility.txt": "ACCESSIBILITY\n  Enabled services:{{com.spy/com.spy.Acc}}\n" + "x" * 50,
            "dumpsys/device_policy.txt": "Device Policy\n  Device Owner:\n    admin=ComponentInfo{com.spy/com.spy.Admin}\n" + "x" * 50,
            "dumpsys/role.txt": "Roles\n    name=android.app.role.SMS\n      holders=com.spy\n" + "x" * 50,
            "dumpsys/appops.txt": "AppOps\n  Uid 10250:\n    Package com.spy:\n      RECORD_AUDIO (allow):\n"
                                  "        Access: [bg-s] 2026-10-20 23:05:00.000 (-1d)\n      SYSTEM_ALERT_WINDOW (allow):\n",
            "dumpsys/adb.txt": "ADB\n  keys:\nQAAAAfakekeymaterial== user@laptop\n" + "x" * 50,
        })
        packages.load_packages(ctx)
        system.analyse_dumpsys(ctx)
        packages.analyse_packages(ctx)
        self.assertIn("com.spy/com.spy.Acc", ctx.enabled["accessibility"])
        self.assertEqual(ctx.enabled["device_owner"], "com.spy/com.spy.Admin")
        self.assertEqual(ctx.enabled["sms"], "com.spy")
        self.assertIn("com.spy", ctx.device["overlayGranted"])
        got = ids(ctx, "com.spy")
        self.assertTrue({"appops.bg", "device.owner", "role.sideloaded", "acc.enabled", "sms.default"} <= got, got)
        self.assertEqual(ctx.device["adb_keys"], ["user@laptop"])
        self.assertTrue(any(e.what.startswith("RECORD_AUDIO used in BACKGROUND") for e in ctx.timeline))

    def test_permission_denied_dumps_are_ignored(self):
        ctx = ctx_for({"dumpsys/package.txt": "Permission Denial: can't dump"})
        system.analyse_dumpsys(ctx)
        self.assertTrue(ctx.coverage["dumpsys"].startswith("MISSING"))


if __name__ == "__main__":
    unittest.main()

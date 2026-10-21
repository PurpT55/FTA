package org.droidsuite.core

import org.droidsuite.core.Fixtures.P
import org.droidsuite.core.Fixtures.TRUSTED
import org.droidsuite.core.Fixtures.app
import org.droidsuite.core.Fixtures.device
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** RiskEngine + AppRules/DeviceRules behaviour, scores, pluggability and HashPolicy. */
class RiskEngineTest {
    private fun run(apps: List<AppRecord>, dev: DeviceState = device(), iocs: IocDb = IocDb(),
                    vt: Map<String, VtVerdict> = emptyMap()) =
        RiskEngine.evaluate(apps, dev, iocs, vt, TRUSTED, setOf("org.droidsuite.sentinel"))

    private fun RiskReport.ids(pkg: String?) = findings.filter { it.pkg == pkg }.map { it.id }.toSet()

    @Test fun storeAppWithCommonPermissionsIsClean() {
        val r = run(listOf(app("com.whatsapp", granted = setOf(P + "CAMERA", P + "RECORD_AUDIO"))))
        assertEquals(emptySet<String>(), r.ids("com.whatsapp"))
        assertEquals(18, r.appScores["com.whatsapp"]!!.privacy)
        assertEquals(0, r.securityRisk)
        assertTrue(r.unknownBinaries.isEmpty())
    }

    @Test fun hiddenSideloadedSpywareProfile() {
        val spy = app("com.systemservice", "System Service", installer = null, launcher = false,
            granted = setOf(P + "ACCESS_FINE_LOCATION", P + "RECORD_AUDIO", P + "READ_SMS", P + "SEND_SMS", P + "READ_CALL_LOG", P + "READ_CONTACTS"))
        val iocs = IocDb().apply { parseText(listOf("package:com.systemservice"), "TheTruthSpy") }
        val r = run(listOf(spy), device(accessibility = listOf("com.systemservice/.Acc"), admins = listOf("com.systemservice/.Adm"),
            overlay = setOf("com.systemservice")), iocs)
        val ids = r.ids("com.systemservice")
        for (id in listOf("ioc.package", "acc.enabled", "admin.active", "overlay.acc", "sms.full", "hidden", "stalkerware.profile",
            "mask.name", "install.untrusted")) assertTrue("missing $id in $ids", id in ids)
        assertEquals(listOf("com.systemservice"), r.malware)
        assertEquals(listOf("com.systemservice"), r.unknownBinaries)
        assertEquals(100, r.securityRisk)
    }

    @Test fun platformKeyStrandHoggAndMasquerade() {
        val apps = listOf(
            app("android", system = true, installer = null, cert = "pp".repeat(32)),
            app("com.whatsapp", "WhatsApp"),
            app("com.evil", "Battery", installer = null, cert = "pp".repeat(32)),
            app("com.google.android.update", "WhatsApp", installer = null,
                components = listOf(ComponentInfo("activity", "x.Login", true, null, taskAffinity = "com.whatsapp"))),
        )
        val r = run(apps)
        assertTrue("cert.platform" in r.ids("com.evil"))
        val fake = r.ids("com.google.android.update")
        assertTrue(fake.containsAll(listOf("task.hijack", "mask.label", "mask.pkg")))
        assertFalse("mask.name" in fake)          // mask.pkg takes precedence
    }

    @Test fun virusTotalVerdicts() {
        val a = app("com.x", installer = null, sha = "a".repeat(64))
        val b = app("com.y", installer = null, sha = "b".repeat(64))
        val vt = mapOf("a".repeat(64) to VtVerdict("a", 12, 70, "trojan", 0), "b".repeat(64) to VtVerdict("b", 1, 70, "adware", 0))
        val r = run(listOf(a, b), vt = vt)
        assertTrue("vt.malicious" in r.ids("com.x"))
        assertTrue("vt.low" in r.ids("com.y"))
        assertTrue(r.unknownBinaries.isEmpty())   // both known to VT
    }

    @Test fun ownPackagesAreIgnored() {
        val r = run(listOf(app("org.droidsuite.sentinel", installer = null, launcher = false, granted = setOf(P + "READ_SMS", P + "SEND_SMS"))))
        assertTrue(r.findings.isEmpty())
    }

    @Test fun deviceRules() {
        val dev = device(props = mapOf("ro.boot.verifiedbootstate" to "orange", "ro.boot.flash.locked" to "0",
            "ro.build.version.security_patch" to "2020-01-05", "ro.build.version.sdk" to "29"), userCas = listOf("CN=Proxy"), lock = false)
        val ids = run(emptyList(), dev).ids(null)
        for (id in listOf("dev.vb", "dev.unlocked", "dev.patch", "dev.eol", "dev.userca", "dev.nolock")) assertTrue("missing $id", id in ids)
        val fresh = DeviceRules.patchLevel { 1_600_000_000_000L }   // 2020-09-13: patch 2020-01-05 is 252 days old
        val out = ArrayList<Finding>()
        fresh.check(device(props = mapOf("ro.build.version.security_patch" to "2020-01-05", "ro.build.version.sdk" to "35")), out)
        assertEquals(Severity.MEDIUM, out.single().severity)
    }

    @Test fun customRuleListIsPluggable() {
        val rule = AppRule { a, _, out -> out += Finding("custom.rule", Severity.LOW, Category.PRIVACY, "x", "", a.pkg) }
        val r = RiskEngine.evaluate(listOf(app("com.a")), device(), IocDb(), emptyMap(), TRUSTED, emptySet(),
            appRules = listOf(rule), deviceRules = emptyList())
        assertEquals(listOf("custom.rule"), r.findings.map { it.id })
    }

    @Test fun hashPolicy() {
        assertTrue(HashPolicy.USER_AND_UPDATED.applies(system = false, updatedSystem = false))
        assertTrue(HashPolicy.USER_AND_UPDATED.applies(system = true, updatedSystem = true))
        assertFalse(HashPolicy.USER_AND_UPDATED.applies(system = true, updatedSystem = false))
        assertTrue(HashPolicy.ALL.applies(system = true, updatedSystem = false))
        assertFalse(HashPolicy.NONE.applies(system = false, updatedSystem = false))
    }
}

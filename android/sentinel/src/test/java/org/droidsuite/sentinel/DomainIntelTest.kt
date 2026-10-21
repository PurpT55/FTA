package org.droidsuite.sentinel

import org.droidsuite.core.IocDb
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Same cases as analyzer/tests/test_logs_network.py::Network.test_classify — keep them aligned. */
class DomainIntelTest {
    private val iocs = IocDb().apply { parseText(listOf("domain:copy9.com"), "TheTruthSpy") }

    @Test fun classification() {
        val cases = mapOf(
            ("copy9.com" to "x") to "IOC:TheTruthSpy",
            ("abc.duckdns.org" to "x") to "dynamic-dns",
            ("x.ngrok-free.app" to "x") to "tunnel-service",
            ("api.telegram.org" to "com.spy") to "telegram-bot-api",
            ("api.telegram.org" to "org.telegram.messenger") to null,
            ("xk2j9qpzvbnw.top" to "x") to "dga-like",
            ("shop.example.xyz" to "x") to "risky-tld",
            ("app-measurement.com" to "x") to "tracker",
            ("connectivitycheck.gstatic.com" to "x") to null,
        )
        for ((k, want) in cases) assertEquals(k.first, want, DomainIntel.classify(k.first, k.second, iocs))
    }

    @Test fun severity() {
        assertTrue(DomainIntel.isSevere("IOC:x"))
        assertTrue(DomainIntel.isSevere("dga-like"))
        assertFalse(DomainIntel.isSevere("tracker"))
        assertFalse(DomainIntel.isSevere("risky-tld"))
    }
}

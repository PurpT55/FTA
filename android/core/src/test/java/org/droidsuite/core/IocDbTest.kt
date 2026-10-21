package org.droidsuite.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class IocDbTest {
    private val yaml = """
        - name: TheTruthSpy
          type: stalkerware
          packages:
          - com.systemservice
          certificates:
          - 31A6ECECD97CF39BC4126B8745CD94A7C30BF81C
          websites:
          - copy9.com
          - 178.63.71.15
          c2:
            ips:
            - 69.64.74.239
            domains:
            - api.thetruth.example
        - name: Other
          type: watchware
          packages:
          - com.other
    """.trimIndent().lines()

    @Test fun parsesStalkerwareIndicatorsFormat() {
        val db = IocDb().apply { parseYaml(yaml) }
        assertEquals("TheTruthSpy", db.packages["com.systemservice"]!!.family)
        assertEquals("watchware", db.packages["com.other"]!!.kind)
        assertEquals("TheTruthSpy", db.certSha1["31a6ececd97cf39bc4126b8745cd94a7c30bf81c"]!!.family)
        assertEquals(setOf("178.63.71.15", "69.64.74.239"), db.ips.keys)
        assertEquals(7, db.size)
    }

    @Test fun domainSuffixMatching() {
        val db = IocDb().apply { parseYaml(yaml) }
        assertEquals("TheTruthSpy", db.matchDomain("WWW.Copy9.com.")!!.family)
        assertEquals("TheTruthSpy", db.matchDomain("x.api.thetruth.example")!!.family)
        assertNull(db.matchDomain("copy9.com.evil.org"))
        assertNull(db.matchDomain("thetruth.example"))
    }

    @Test fun plainTextLists() {
        val db = IocDb().apply { parseText(listOf("# c", "package:com.x", "domain:Evil.Example", "sha256:AB", "cert:CD", "junk"), "mine") }
        assertEquals("mine", db.packages["com.x"]!!.family)
        assertEquals(setOf("evil.example"), db.domains.keys)
        assertEquals(setOf("ab"), db.hashes.keys)
        assertEquals(setOf("cd"), db.certSha1.keys)
    }
}

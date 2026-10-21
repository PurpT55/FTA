package org.droidsuite.sentinel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DnsPacketTest {
    /** IPv4/UDP datagram 10.111.222.1:40000 -> 10.111.222.2:53 carrying a DNS query for [name]. */
    private fun query(name: String, qtype: Int = 1, proto: Int = 17, dstPort: Int = 53): ByteArray {
        val dns = ArrayList<Byte>()
        listOf(0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0).forEach { dns += it.toByte() }   // header, 1 question
        name.split('.').forEach { label -> dns += label.length.toByte(); label.forEach { dns += it.code.toByte() } }
        dns += 0
        dns += (qtype shr 8).toByte(); dns += qtype.toByte(); dns += 0; dns += 1                 // QTYPE, QCLASS IN
        val total = 28 + dns.size
        val p = ByteArray(total)
        p[0] = 0x45; p[2] = (total shr 8).toByte(); p[3] = total.toByte(); p[8] = 64; p[9] = proto.toByte()
        byteArrayOf(10, 111, 222.toByte(), 1).copyInto(p, 12)
        byteArrayOf(10, 111, 222.toByte(), 2).copyInto(p, 16)
        p[20] = (40000 shr 8).toByte(); p[21] = 40000.toByte()
        p[22] = (dstPort shr 8).toByte(); p[23] = dstPort.toByte()
        val ul = 8 + dns.size
        p[24] = (ul shr 8).toByte(); p[25] = ul.toByte()
        dns.toByteArray().copyInto(p, 28)
        return p
    }

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)

    @Test fun parsesQuery() {
        val pkt = query("API.Telegram.org", qtype = 28)
        val q = DnsPacket.parseQuery(pkt, pkt.size)!!
        assertEquals("api.telegram.org", q.name)
        assertEquals(28, q.qtype)
        assertEquals(40000, q.srcPort)
        assertEquals(53, q.dstPort)
    }

    @Test fun rejectsNonDns() {
        val tcp = query("a.com", proto = 6)
        assertNull(DnsPacket.parseQuery(tcp, tcp.size))
        val other = query("a.com", dstPort = 853)
        assertNull(DnsPacket.parseQuery(other, other.size))
        assertNull(DnsPacket.parseQuery(ByteArray(10), 10))
    }

    @Test fun buildsValidResponse() {
        val pkt = query("example.com")
        val q = DnsPacket.parseQuery(pkt, pkt.size)!!
        val answer = byteArrayOf(0x12, 0x34, 0x81.toByte(), 0x80.toByte(), 0, 1, 0, 0, 0, 0, 0, 0)
        val r = DnsPacket.buildResponse(q, answer)
        assertEquals(28 + answer.size, u16(r, 2))                  // IPv4 total length
        assertArrayEquals(q.dstIp, r.copyOfRange(12, 16))          // addresses swapped
        assertArrayEquals(q.srcIp, r.copyOfRange(16, 20))
        assertEquals(53, u16(r, 20))
        assertEquals(40000, u16(r, 22))
        var sum = 0L                                               // header checksum verifies to 0xffff
        for (i in 0 until 20 step 2) sum += u16(r, i)
        while (sum shr 16 != 0L) sum = (sum and 0xffff) + (sum shr 16)
        assertEquals(0xffff, sum.toInt())
        assertArrayEquals(answer, r.copyOfRange(28, r.size))
    }
}

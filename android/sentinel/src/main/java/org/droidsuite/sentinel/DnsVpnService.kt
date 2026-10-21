package org.droidsuite.sentinel

import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import org.droidsuite.core.Category
import org.droidsuite.core.IocDb
import org.droidsuite.core.Severity
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Executors

/**
 * "DNS-only" local VPN. Only the fake resolver address 10.111.222.2 is routed into
 * the tunnel, so normal traffic never touches this app. Every DNS query is
 * attributed to the requesting app (Android 10+), logged, classified, and forwarded
 * unchanged to the real resolver of the underlying network.
 *
 * Limits: apps using DNS-over-HTTPS / hard-coded resolvers, or "strict" Private DNS,
 * bypass this monitor. Use PCAPdroid for full packet capture.
 */
class DnsVpnService : VpnService() {
    companion object {
        const val ACTION_STOP = "stop"
        const val TUN_ADDR = "10.111.222.1"
        const val DNS_ADDR = "10.111.222.2"
        @Volatile var running = false
    }

    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null
    private val pool = Executors.newFixedThreadPool(4)
    private lateinit var store: Store
    private var iocs: IocDb? = null
    private var upstream: List<InetAddress> = emptyList()
    private val uidCache = HashMap<Int, String>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopVpn(); return START_NOT_STICKY }
        store = Store.get(this)
        val n = Notifier.ongoing(this, "DNS monitor active")
        if (Build.VERSION.SDK_INT >= 34) startForeground(2, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        else startForeground(2, n)
        if (tun == null) start()
        return START_STICKY
    }

    private fun start() {
        iocs = Scanner.iocs(this)
        val cm = getSystemService(ConnectivityManager::class.java)
        upstream = try {
            cm.getLinkProperties(cm.activeNetwork)?.dnsServers?.filterIsInstance<Inet4Address>() ?: emptyList()
        } catch (_: Exception) { emptyList() }
        if (upstream.isEmpty()) upstream = listOf(InetAddress.getByName("9.9.9.9"))
        val b = Builder().setSession("DroidSentinel DNS monitor")
            .addAddress(TUN_ADDR, 32)
            .addRoute(DNS_ADDR, 32)
            .addDnsServer(DNS_ADDR)
            .setBlocking(true)
        try { b.addDisallowedApplication(packageName) } catch (_: Exception) { }
        tun = b.establish()
        if (tun == null) { stopSelf(); return }
        running = true
        store.dnsEnabled = true
        worker = Thread({ loop() }, "dns-tun").also { it.start() }
    }

    private fun loop() {
        val fd = tun ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        try {
            while (running) {
                val n = input.read(buf)
                if (n <= 0) continue
                val q = DnsPacket.parseQuery(buf, n) ?: continue
                pool.execute { handle(q, output) }
            }
        } catch (_: Exception) {
        }
    }

    private fun owner(q: DnsPacket.Query): String {
        if (Build.VERSION.SDK_INT < 29) return "unknown"
        return try {
            val cm = getSystemService(ConnectivityManager::class.java)
            val uid = cm.getConnectionOwnerUid(
                OsConstants.IPPROTO_UDP,
                InetSocketAddress(InetAddress.getByAddress(q.srcIp), q.srcPort),
                InetSocketAddress(InetAddress.getByAddress(q.dstIp), q.dstPort),
            )
            if (uid < 0) "unknown" else synchronized(uidCache) {
                uidCache.getOrPut(uid) { packageManager.getPackagesForUid(uid)?.joinToString("|") ?: "uid:$uid" }
            }
        } catch (_: Exception) { "unknown" }
    }

    private fun handle(q: DnsPacket.Query, output: FileOutputStream) {
        val pkg = owner(q)
        val flag = DomainIntel.classify(q.name, pkg, iocs)
        try {
            val firstTime = !store.knownDomainForPkg(pkg, q.name)
            store.addDns(DnsRow(System.currentTimeMillis(), pkg, q.name, q.qtype, flag))
            if (flag != null && DomainIntel.isSevere(flag) && firstTime) {
                val sev = if (flag.startsWith("IOC:")) Severity.CRITICAL else Severity.MEDIUM
                store.addEvent(Event(System.currentTimeMillis(), sev, if (sev == Severity.CRITICAL) Category.MALWARE else Category.SUSPICIOUS,
                    pkg, "dns", "Suspicious DNS lookup ($flag)", q.name))
                if (sev == Severity.CRITICAL || flag == "telegram-bot-api") Notifier.alert(this, "Suspicious domain: ${q.name}", "$pkg ($flag)")
            }
        } catch (_: Exception) { }
        // Forward to the real resolver on a protected socket (bypasses our own tunnel).
        for (server in upstream) {
            try {
                DatagramSocket().use { s ->
                    protect(s)
                    s.soTimeout = 5000
                    s.send(DatagramPacket(q.payload, q.payload.size, server, 53))
                    val resp = ByteArray(4096)
                    val p = DatagramPacket(resp, resp.size)
                    s.receive(p)
                    val pkt = DnsPacket.buildResponse(q, resp.copyOf(p.length))
                    synchronized(output) { output.write(pkt) }
                }
                return
            } catch (_: Exception) {
            }
        }
    }

    private fun stopVpn() {
        running = false
        store = Store.get(this)
        store.dnsEnabled = false
        try { tun?.close() } catch (_: Exception) { }
        tun = null
        worker?.interrupt()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() { stopVpn() }

    override fun onDestroy() {
        running = false
        try { tun?.close() } catch (_: Exception) { }
        pool.shutdownNow()
        super.onDestroy()
    }
}

/** Minimal IPv4/UDP/DNS packet handling for the DNS tunnel. */
object DnsPacket {
    class Query(
        val srcIp: ByteArray, val dstIp: ByteArray, val srcPort: Int, val dstPort: Int,
        val payload: ByteArray, val name: String, val qtype: Int,
    )

    fun parseQuery(b: ByteArray, len: Int): Query? {
        if (len < 28 || (b[0].toInt() shr 4) != 4) return null
        val ihl = (b[0].toInt() and 0x0f) * 4
        if (b[9].toInt() != 17 || len < ihl + 8) return null   // UDP only
        val srcIp = b.copyOfRange(12, 16)
        val dstIp = b.copyOfRange(16, 20)
        val srcPort = u16(b, ihl)
        val dstPort = u16(b, ihl + 2)
        if (dstPort != 53) return null
        val udpLen = u16(b, ihl + 4)
        val payloadEnd = minOf(len, ihl + udpLen)
        val payload = b.copyOfRange(ihl + 8, payloadEnd)
        if (payload.size < 12) return null
        // Question name starts at offset 12 of the DNS message.
        val sb = StringBuilder()
        var i = 12
        while (i < payload.size) {
            val l = payload[i].toInt() and 0xff
            if (l == 0) { i++; break }
            if (l and 0xc0 != 0 || i + 1 + l > payload.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (k in 1..l) sb.append((payload[i + k].toInt() and 0xff).toChar())
            i += l + 1
        }
        val qtype = if (i + 2 <= payload.size) u16(payload, i) else 0
        return Query(srcIp, dstIp, srcPort, dstPort, payload, sb.toString().lowercase(), qtype)
    }

    fun buildResponse(q: Query, dns: ByteArray): ByteArray {
        val total = 20 + 8 + dns.size
        val p = ByteArray(total)
        p[0] = 0x45; p[2] = (total shr 8).toByte(); p[3] = total.toByte()
        p[6] = 0x40                       // don't fragment
        p[8] = 64; p[9] = 17              // TTL, UDP
        System.arraycopy(q.dstIp, 0, p, 12, 4)
        System.arraycopy(q.srcIp, 0, p, 16, 4)
        val cs = checksum(p, 0, 20)
        p[10] = (cs shr 8).toByte(); p[11] = cs.toByte()
        p[20] = (q.dstPort shr 8).toByte(); p[21] = q.dstPort.toByte()
        p[22] = (q.srcPort shr 8).toByte(); p[23] = q.srcPort.toByte()
        val ul = 8 + dns.size
        p[24] = (ul shr 8).toByte(); p[25] = ul.toByte()
        // UDP checksum 0 = "not computed", valid for IPv4.
        System.arraycopy(dns, 0, p, 28, dns.size)
        return p
    }

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 8) or (b[o + 1].toInt() and 0xff)

    private fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        while (i < off + len - 1) { sum += u16(b, i); i += 2 }
        if (len % 2 == 1) sum += (b[off + len - 1].toInt() and 0xff) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xffff) + (sum shr 16)
        return sum.inv().toInt() and 0xffff
    }
}

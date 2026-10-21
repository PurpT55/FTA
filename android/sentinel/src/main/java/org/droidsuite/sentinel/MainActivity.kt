package org.droidsuite.sentinel

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.widget.CheckBox
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Toast
import org.droidsuite.core.AppRecord
import org.droidsuite.core.Category
import org.droidsuite.core.Finding
import org.droidsuite.core.RiskEngine
import org.droidsuite.core.Severity
import org.droidsuite.core.Ui
import org.droidsuite.core.Util
import org.droidsuite.core.hasUsageAccess
import java.io.File
import java.net.URL

class MainActivity : Activity() {
    companion object {
        const val REQ_VPN = 10
        const val REQ_EXPORT = 11
        const val REQ_IOC = 12
        const val ECHAP_IOC = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
    }

    private lateinit var store: Store
    private lateinit var content: LinearLayout
    private lateinit var tabs: LinearLayout
    private var tab = "Dashboard"
    private var showSystem = false
    private var findingFilter: Category? = null
    @Volatile private var scanning = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        store = Store.get(this)
        Notifier.channels(this)
        val root = Ui.vbox(this).apply { setBackgroundColor(Ui.BG) }
        tabs = Ui.hbox(this)
        root.addView(HorizontalScrollView(this).apply { addView(tabs) })
        content = Ui.vbox(this, 12)
        root.addView(ScrollView(this).apply { addView(content) }, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf("android.permission.POST_NOTIFICATIONS"), 1)
        if (Scanner.last == null) runScan() else render()
    }

    override fun onResume() { super.onResume(); render() }

    // ------------------------------------------------------------------ helpers
    private fun bg(work: () -> Unit) = Thread {
        try { work() } catch (e: Exception) { runOnUiThread { toast("Error: ${e.message}") } }
        runOnUiThread { render() }
    }.start()

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()

    private fun runScan() {
        if (scanning.isNotEmpty()) return
        scanning = "Starting…"
        render()
        bg {
            Scanner.scan(this) { i, n -> if (i % 10 == 0) { scanning = "Scanning $i/$n"; runOnUiThread { render() } } }
            scanning = ""
        }
    }

    private fun add(v: View) = content.addView(v)
    private fun h(s: String) = add(Ui.text(this, s, 18f, Ui.TEXT, true).apply { setPadding(0, Ui.dp(this@MainActivity, 14), 0, Ui.dp(this@MainActivity, 4)) })
    private fun p(s: CharSequence, color: Int = Ui.MUTED, size: Float = 13f) = add(Ui.text(this, s, size, color))
    private fun row(vararg buttons: Pair<String, () -> Unit>) = add(Ui.hbox(this).apply {
        buttons.forEach { (l, a) -> addView(Ui.weighted(Ui.button(this@MainActivity, l, a))) }
    })

    private fun render() {
        tabs.removeAllViews()
        listOf("Dashboard", "Findings", "Apps", "Network", "Events", "Settings").forEach { t ->
            tabs.addView(Ui.button(this, if (t == tab) "● $t" else t) { tab = t; render() })
        }
        content.removeAllViews()
        if (scanning.isNotEmpty()) p("⏳ $scanning", Ui.ACCENT, 15f)
        when (tab) {
            "Dashboard" -> dashboard()
            "Findings" -> findings()
            "Apps" -> apps()
            "Network" -> network()
            "Events" -> events()
            "Settings" -> settings()
        }
    }

    // ------------------------------------------------------------------ dashboard
    private fun scoreCard(title: String, value: String, sub: String, color: Int, onClick: () -> Unit): View =
        Ui.card(this, color).apply {
            addView(Ui.text(this@MainActivity, title, 12f, Ui.MUTED))
            addView(Ui.text(this@MainActivity, value, 28f, color, true))
            addView(Ui.text(this@MainActivity, sub, 11f, Ui.MUTED))
            setOnClickListener { onClick() }
        }

    private fun dashboard() {
        val r = Scanner.last
        add(Ui.text(this, "DroidSentinel", 24f, Ui.TEXT, true))
        p(if (r == null) "No scan yet" else "Last scan ${Util.local(r.ts)} · ${r.apps.size} packages")
        if (r != null) {
            val rep = r.report
            val day = System.currentTimeMillis() - 86_400_000L
            val ev24 = store.events(day, 2000).count { it.severity >= Severity.MEDIUM }
            val g1 = Ui.hbox(this); val g2 = Ui.hbox(this); val g3 = Ui.hbox(this)
            g1.addView(Ui.weighted(scoreCard("Privacy risk", "${rep.privacyRisk}/100", "data-access exposure", Ui.scoreColor(rep.privacyRisk)) { tab = "Apps"; render() }))
            g1.addView(Ui.weighted(scoreCard("Security risk", "${rep.securityRisk}/100", "device + app weaknesses", Ui.scoreColor(rep.securityRisk)) { findingFilter = Category.SECURITY; tab = "Findings"; render() }))
            g2.addView(Ui.weighted(scoreCard("Suspicious activity", "${rep.suspicious + ev24}", "${rep.suspicious} findings · $ev24 events/24h",
                if (rep.suspicious + ev24 > 0) Ui.sevColor(Severity.HIGH) else Ui.scoreColor(0)) { findingFilter = Category.SUSPICIOUS; tab = "Findings"; render() }))
            g2.addView(Ui.weighted(scoreCard("Unknown binaries", "${rep.unknownBinaries.size}", "sideloaded, unknown to VT",
                if (rep.unknownBinaries.isNotEmpty()) Ui.sevColor(Severity.MEDIUM) else Ui.scoreColor(0)) { findingFilter = Category.UNKNOWN; tab = "Findings"; render() }))
            g3.addView(Ui.weighted(scoreCard("Malware detected", "${rep.malware.size}", rep.malware.take(3).joinToString().ifEmpty { "IOC + VirusTotal" },
                if (rep.malware.isNotEmpty()) Ui.sevColor(Severity.CRITICAL) else Ui.scoreColor(0)) { findingFilter = Category.MALWARE; tab = "Findings"; render() }))
            add(g1); add(g2); add(g3)
        }

        h("Monitoring")
        val usage = hasUsageAccess(this)
        p("Real-time monitor: ${if (MonitorService.running) "ON" else "off"}   ·   DNS monitor: ${if (DnsVpnService.running) "ON" else "off"}")
        p("Usage access (traffic per app): ${if (usage) "granted" else "MISSING"}   ·   VirusTotal: ${if (store.vtKey.isBlank()) "no API key" else "configured, ${VtClient.queued} queued"}")
        row("Scan now" to { runScan() },
            (if (MonitorService.running) "Stop monitor" else "Start monitor") to {
                if (MonitorService.running) MonitorService.stop(this) else MonitorService.start(this)
                content.postDelayed({ render() }, 500)
            })
        row((if (DnsVpnService.running) "Stop DNS monitor" else "Start DNS monitor") to { toggleDns() },
            "VirusTotal check apps" to {
                val r2 = Scanner.last
                if (store.vtKey.isBlank()) { tab = "Settings"; render(); toast("Add a VirusTotal API key first") }
                else if (r2 != null) { Scanner.queueVt(this, r2) { runOnUiThread { toast("VirusTotal lookups finished") } }; toast("Hash lookups queued (≈4/min, hashes only)") }
            })
        if (!usage) row("Grant usage access" to { startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) },
            "Battery: don't optimise" to { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) })

        if (r != null) {
            h("Top findings")
            val top = r.report.findings.filter { it.severity >= Severity.HIGH }.take(8)
            if (top.isEmpty()) p("No high or critical findings. 🎉", Ui.scoreColor(0))
            top.forEach { add(findingView(it)) }
            h("Recent alerts")
            store.events(0, 5).forEach { add(eventView(it)) }
        }
    }

    private fun toggleDns() {
        if (DnsVpnService.running) {
            startService(Intent(this, DnsVpnService::class.java).setAction(DnsVpnService.ACTION_STOP))
            content.postDelayed({ render() }, 500)
            return
        }
        val i = VpnService.prepare(this)
        if (i != null) startActivityForResult(i, REQ_VPN) else onActivityResult(REQ_VPN, RESULT_OK, null)
    }

    // ------------------------------------------------------------------ findings
    private fun findingView(f: Finding): View = Ui.card(this, Ui.sevColor(f.severity)).apply {
        addView(Ui.hbox(this@MainActivity).apply {
            addView(Ui.chip(this@MainActivity, f.severity.name, Ui.sevColor(f.severity)))
            addView(Ui.text(this@MainActivity, "  ${f.category.name.lowercase()}", 11f, Ui.MUTED))
        })
        addView(Ui.text(this@MainActivity, f.title, 15f, Ui.TEXT, true))
        val app = f.pkg?.let { p -> Scanner.last?.apps?.firstOrNull { it.pkg == p } }
        if (f.pkg != null) addView(Ui.text(this@MainActivity, "${app?.label ?: ""}  ${f.pkg}", 12f, Ui.ACCENT))
        setOnClickListener {
            if (app != null) appDialog(app) else AlertDialog.Builder(this@MainActivity).setTitle(f.title)
                .setMessage(f.detail + (f.mitre?.let { "\n\nMITRE ATT&CK Mobile: $it" } ?: "")).setPositiveButton("OK", null).show()
        }
    }

    private fun findings() {
        val r = Scanner.last ?: return p("Run a scan first.")
        h("Findings")
        add(HorizontalScrollView(this).apply {
            addView(Ui.hbox(this@MainActivity).apply {
                addView(Ui.button(this@MainActivity, if (findingFilter == null) "● All" else "All") { findingFilter = null; render() })
                Category.values().forEach { c ->
                    addView(Ui.button(this@MainActivity, (if (findingFilter == c) "● " else "") + c.name.lowercase()) { findingFilter = c; render() })
                }
            })
        })
        val list = r.report.findings.filter { findingFilter == null || it.category == findingFilter }.filter { it.severity > Severity.INFO || findingFilter != null }
        p("${list.size} findings (tap for details)")
        list.take(300).forEach { add(findingView(it)) }
    }

    // ------------------------------------------------------------------ apps
    private fun apps() {
        val r = Scanner.last ?: return p("Run a scan first.")
        h("Applications")
        val cb = CheckBox(this).apply {
            text = "Show system apps"; setTextColor(Ui.TEXT); isChecked = showSystem
            setOnCheckedChangeListener { _, b -> showSystem = b; render() }
        }
        add(cb)
        val vt = store.vtAll()
        val trusted = store.trustedInstallers
        val list = r.apps.filter { showSystem || !it.system }
            .sortedWith(compareByDescending<AppRecord> { r.report.appScores[it.pkg]?.security ?: 0 }.thenByDescending { r.report.appScores[it.pkg]?.privacy ?: 0 })
        p("${list.size} apps · sorted by security then privacy risk")
        list.forEach { a ->
            val s = r.report.appScores[a.pkg]
            add(Ui.card(this).apply {
                addView(Ui.text(this@MainActivity, a.label, 15f, Ui.TEXT, true))
                addView(Ui.text(this@MainActivity, a.pkg, 11f, Ui.MUTED))
                addView(Ui.hbox(this@MainActivity).apply {
                    addView(Ui.chip(this@MainActivity, "Privacy ${s?.privacy ?: 0}", Ui.scoreColor(s?.privacy ?: 0)))
                    addView(Ui.text(this@MainActivity, " ", 11f))
                    addView(Ui.chip(this@MainActivity, "Security ${s?.security ?: 0}", Ui.scoreColor(s?.security ?: 0)))
                    addView(Ui.text(this@MainActivity, " ", 11f))
                    val src = when {
                        a.system -> "system"
                        a.installer in trusted -> "store"
                        else -> "sideloaded"
                    }
                    addView(Ui.chip(this@MainActivity, src, if (src == "sideloaded") Ui.sevColor(Severity.MEDIUM) else Ui.MUTED))
                    addView(Ui.text(this@MainActivity, " ", 11f))
                    val v = a.apkSha256?.let { vt[it] }
                    val (vl, vc) = when {
                        v == null -> "VT ?" to Ui.MUTED
                        v.positives < 0 -> "VT unknown" to Ui.sevColor(Severity.MEDIUM)
                        v.positives == 0 -> "VT 0/${v.total}" to Ui.scoreColor(0)
                        else -> "VT ${v.positives}/${v.total}" to Ui.sevColor(if (v.positives >= 3) Severity.CRITICAL else Severity.MEDIUM)
                    }
                    addView(Ui.chip(this@MainActivity, vl, vc))
                })
                setOnClickListener { appDialog(a) }
            })
        }
    }

    private fun appDialog(a: AppRecord) {
        val r = Scanner.last
        val vt = a.apkSha256?.let { store.vtAll()[it] }
        val fs = r?.report?.findings?.filter { it.pkg == a.pkg }.orEmpty()
        val sb = StringBuilder()
        sb.append("Package: ${a.pkg}\nVersion: ${a.versionName} (${a.versionCode})\nInstaller: ${a.installer ?: "none/adb"}")
        a.initiatingInstaller?.let { sb.append(" (initiated by $it)") }
        sb.append("\nInstalled: ${Util.local(a.firstInstall)}\nUpdated: ${Util.local(a.lastUpdate)}")
        sb.append("\nSystem: ${a.system}  Launcher icon: ${a.hasLauncher}  targetSdk: ${a.targetSdk}")
        sb.append("\nAPK: ${a.apkPaths.firstOrNull()} (${Util.humanBytes(a.apkSize)})\nSHA-256: ${a.apkSha256}")
        sb.append("\nSigner SHA-256: ${a.certSha256.joinToString()}\nSigner: ${a.certSubjects.joinToString()}")
        sb.append("\nVirusTotal: ").append(
            when {
                vt == null -> "not checked"
                vt.positives < 0 -> "unknown to VirusTotal"
                else -> "${vt.positives}/${vt.total} ${vt.label ?: ""}"
            }
        )
        if (fs.isNotEmpty()) {
            sb.append("\n\nFINDINGS\n")
            fs.forEach { sb.append("• [${it.severity}] ${it.title}${it.mitre?.let { m -> " ($m)" } ?: ""}\n  ${it.detail}\n") }
        }
        val dangerous = a.granted.filter { it in RiskEngine.PRIVACY_WEIGHTS }
        if (dangerous.isNotEmpty()) sb.append("\nSENSITIVE PERMISSIONS GRANTED\n").append(dangerous.joinToString("\n") { "• " + it.substringAfterLast('.') })
        val exported = a.components.filter { it.exported }
        sb.append("\n\nCOMPONENTS: ${a.components.size} (${exported.size} exported)")
        a.components.filter { it.type == "service" && it.permission?.startsWith("android.permission.BIND_") == true }
            .forEach { sb.append("\n• binds ${it.permission!!.removePrefix("android.permission.")}: ${it.name}") }
        if (a.nativeLibs.isNotEmpty()) sb.append("\nNative libs: ${a.nativeLibs.joinToString()}")
        val domains = store.dnsSummary()[a.pkg]?.entries?.sortedByDescending { it.value }?.take(25)
        if (!domains.isNullOrEmpty()) sb.append("\n\nDNS LOOKUPS\n").append(domains.joinToString("\n") { "• ${it.key} ×${it.value}" })
        store.trafficSummary(System.currentTimeMillis() - 86_400_000L)[a.pkg]?.let {
            sb.append("\n\nTRAFFIC 24h: ↓${Util.humanBytes(it[0])} ↑${Util.humanBytes(it[1])} (↑ screen off ${Util.humanBytes(it[2])})")
        }
        val dlg = AlertDialog.Builder(this).setTitle(a.label).setMessage(sb)
            .setPositiveButton("Close", null)
            .setNeutralButton("App settings") { _, _ ->
                startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${a.pkg}")))
            }
            .setNegativeButton("VirusTotal…") { _, _ -> vtMenu(a) }
            .create()
        dlg.show()
    }

    private fun vtMenu(a: AppRecord) {
        if (store.vtKey.isBlank()) { toast("Add a VirusTotal API key in Settings"); return }
        val sha = a.apkSha256 ?: return toast("No hash available")
        AlertDialog.Builder(this).setTitle("VirusTotal")
            .setItems(arrayOf("Look up hash (sends only the SHA-256)", "Copy SHA-256", "Upload APK file…")) { _, which ->
                when (which) {
                    0 -> bg {
                        val v = VtClient(this).lookupHash(sha)
                        store.putVt(v, a.pkg)
                        runOnUiThread { toast(if (v.positives < 0) "Unknown to VirusTotal" else "${v.positives}/${v.total} detections") }
                    }
                    1 -> {
                        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("sha256", sha))
                        toast("Copied")
                    }
                    2 -> confirmUpload(a)
                }
            }.show()
    }

    /** The only path that sends file content off the device. Two explicit confirmations. */
    private fun confirmUpload(a: AppRecord) {
        val f = File(a.apkPaths.firstOrNull() ?: return)
        AlertDialog.Builder(this).setTitle("Upload ${f.name} to VirusTotal?")
            .setMessage(
                "File: ${f.path}\nSize: ${Util.humanBytes(f.length())}\nSHA-256: ${a.apkSha256}\n\n" +
                    "The FILE will be sent to VirusTotal. Uploaded samples are shared with security vendors and can be " +
                    "downloaded by VirusTotal premium users. Do not upload private/enterprise apps or apps that may embed " +
                    "personal data. Split APKs are not uploaded."
            )
            .setNegativeButton("Cancel", null)
            .setPositiveButton("I understand – upload") { _, _ ->
                bg {
                    val id = VtClient(this).uploadFile(f)
                    store.addEvent(Event(System.currentTimeMillis(), Severity.INFO, Category.UNKNOWN, a.pkg, "vt.upload",
                        "APK uploaded to VirusTotal by user", "analysis id $id"))
                    runOnUiThread { toast("Uploaded. Re-run the hash lookup in a few minutes.") }
                }
            }.show()
    }

    // ------------------------------------------------------------------ network
    private fun network() {
        h("Traffic per app (24h)")
        if (!hasUsageAccess(this)) row("Grant usage access" to { startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) })
        val t = store.trafficSummary(System.currentTimeMillis() - 86_400_000L).entries.sortedByDescending { it.value[1] }.take(25)
        if (t.isEmpty()) p("No data yet. Start the monitor; statistics arrive with a few minutes of delay.")
        t.forEach { (pkg, v) ->
            p("↑${Util.humanBytes(v[1])}  ↓${Util.humanBytes(v[0])}  (↑off ${Util.humanBytes(v[2])})  $pkg",
                if (v[2] > store.bgUploadThresholdMb * 1048576L) Ui.sevColor(Severity.HIGH) else Ui.TEXT)
        }
        h("Flagged DNS lookups")
        if (!DnsVpnService.running) p("DNS monitor is off. Start it on the Dashboard to see which app contacts which domain.")
        val flagged = store.dns(200, true)
        if (flagged.isEmpty()) p("None.")
        flagged.forEach { add(dnsView(it)) }
        h("Recent DNS lookups")
        store.dns(150).forEach { add(dnsView(it)) }
    }

    private fun dnsView(d: DnsRow): View = Ui.text(
        this, "${Util.local(d.ts).substring(11)}  ${d.domain}\n      ${d.pkg}${d.flag?.let { "  ⚑ $it" } ?: ""}", 12f,
        if (d.flag == null) Ui.TEXT else if (DomainIntel.isSevere(d.flag)) Ui.sevColor(Severity.HIGH) else Ui.sevColor(Severity.MEDIUM)
    ).apply {
        setPadding(0, 6, 0, 6)
        setOnClickListener {
            AlertDialog.Builder(this@MainActivity).setTitle(d.domain)
                .setMessage("Requested by ${d.pkg}\nFlag: ${d.flag ?: "none"}\n\nLook up this domain's reputation on VirusTotal? Only the domain name is sent.")
                .setPositiveButton("Look up") { _, _ ->
                    if (store.vtKey.isBlank()) toast("No API key") else bg {
                        val (m, tot) = VtClient(this@MainActivity).lookupDomain(d.domain)
                        runOnUiThread { toast(if (m < 0) "Unknown domain" else "${d.domain}: $m/$tot engines flag it") }
                    }
                }.setNegativeButton("Close", null).show()
        }
    }

    // ------------------------------------------------------------------ events
    private fun eventView(e: Event): View = Ui.card(this, Ui.sevColor(e.severity)).apply {
        addView(Ui.text(this@MainActivity, "${Util.local(e.ts)}  ${e.severity}  ${e.type}", 11f, Ui.MUTED))
        addView(Ui.text(this@MainActivity, e.title, 14f, Ui.TEXT, true))
        if (e.pkg != null) addView(Ui.text(this@MainActivity, e.pkg, 11f, Ui.ACCENT))
        if (e.detail.isNotEmpty()) addView(Ui.text(this@MainActivity, e.detail.take(300), 12f, Ui.MUTED))
    }

    private fun events() {
        h("Event timeline")
        val ev = store.events(0, 300)
        if (ev.isEmpty()) p("No events yet.")
        ev.forEach { add(eventView(it)) }
    }

    // ------------------------------------------------------------------ settings
    private fun settings() {
        h("VirusTotal")
        p("Free key: virustotal.com → sign up → API key. Limits: 4 lookups/min, 500/day. " +
            "Only SHA-256 hashes are sent automatically; files are uploaded only when you confirm it for one app.")
        val key = EditText(this).apply {
            setText(store.vtKey); hint = "VirusTotal API key"; setTextColor(Ui.TEXT); setHintTextColor(Ui.MUTED)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        add(key)
        add(CheckBox(this).apply {
            text = "Automatically look up hashes of user apps after each scan"; setTextColor(Ui.TEXT); isChecked = store.autoVt
            setOnCheckedChangeListener { _, b -> store.autoVt = b }
        })
        row("Save key" to { store.vtKey = key.text.toString(); toast("Saved") })

        h("Trusted installers")
        p("Apps installed by other installers count as sideloaded / unknown.")
        val inst = EditText(this).apply { setText(store.trustedInstallers.sorted().joinToString(",")); setTextColor(Ui.TEXT) }
        add(inst)
        row("Save" to { store.trustedInstallers = inst.text.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet(); toast("Saved") },
            "Reset" to { store.prefs.edit().remove("trusted").apply(); render() })

        h("Background upload alert threshold (MB)")
        val thr = EditText(this).apply { setText(store.bgUploadThresholdMb.toString()); inputType = InputType.TYPE_CLASS_NUMBER; setTextColor(Ui.TEXT) }
        add(thr)
        row("Save" to { store.bgUploadThresholdMb = thr.text.toString().toIntOrNull() ?: 5; toast("Saved") })

        h("Indicators of compromise")
        val iocDir = File(filesDir, "iocs").apply { mkdirs() }
        p("${Scanner.iocs(this).size} indicators loaded from ${iocDir.listFiles()?.size ?: 0} file(s).")
        row("Download stalkerware IOCs" to {
            bg {
                val txt = URL(ECHAP_IOC).readText()
                File(iocDir, "stalkerware-indicators.yaml").writeText(txt)
                runOnUiThread { toast("IOC list updated"); runScan() }
            }
        }, "Import file…" to {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), REQ_IOC)
        })
        p("Source: github.com/AssoEchap/stalkerware-indicators (download sends no data about you). " +
            "Custom .txt lists accept lines like package:com.x, domain:evil.com, sha256:…, cert:<sha1>.")

        h("Report")
        row("Export JSON report…" to {
            startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/json").putExtra(Intent.EXTRA_TITLE, "sentinel-report-${System.currentTimeMillis() / 1000}.json"), REQ_EXPORT)
        })
        h("About")
        p("DroidSentinel uses QUERY_ALL_PACKAGES, a local VPN and usage access – the same capabilities it warns about. " +
            "Everything stays on the device; nothing is sent anywhere except VirusTotal lookups you enabled.")
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK) return
        when (requestCode) {
            REQ_VPN -> {
                startForegroundService(Intent(this, DnsVpnService::class.java))
                content.postDelayed({ render() }, 800)
            }
            REQ_EXPORT -> data?.data?.let { uri ->
                bg {
                    val r = Scanner.last ?: Scanner.scan(this)
                    contentResolver.openOutputStream(uri)?.use { it.write(Scanner.reportJson(this, r).toString(1).toByteArray()) }
                    runOnUiThread { toast("Report exported") }
                }
            }
            REQ_IOC -> data?.data?.let { uri ->
                bg {
                    val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: ByteArray(0)
                    // ioc.yaml entries start with "- name:"; anything else is treated as a plain list.
                    val name = "import-${System.currentTimeMillis()}" + if (String(bytes).contains("- name:")) ".yaml" else ".txt"
                    File(File(filesDir, "iocs").apply { mkdirs() }, name).writeBytes(bytes)
                    runOnUiThread { toast("Imported $name") }
                }
            }
        }
    }
}

package org.droidsuite.collector

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.WindowManager
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.droidsuite.core.Ui
import org.droidsuite.core.Util
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * DroidCollector UI: shows which capabilities are granted (READ_LOGS, DUMP, usage access, Sentinel
 * report), lets the user pick [Section]s, asks for explicit consent, then the destination file
 * (ACTION_CREATE_DOCUMENT), and runs [Collector] on a background thread.
 */
class MainActivity : Activity() {
    companion object { const val REQ_DEST = 20 }

    private lateinit var content: LinearLayout
    private lateinit var status: TextView
    private val boxes = LinkedHashMap<Section, CheckBox>()
    @Volatile private var busy = false

    private val adbCmds = """
        adb shell pm grant org.droidsuite.collector android.permission.READ_LOGS
        adb shell pm grant org.droidsuite.collector android.permission.DUMP
        adb shell appops set org.droidsuite.collector GET_USAGE_STATS allow
    """.trimIndent()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        content = Ui.vbox(this, 14).apply { setBackgroundColor(Ui.BG) }
        setContentView(ScrollView(this).apply { setBackgroundColor(Ui.BG); addView(content) })
        build()
    }

    override fun onResume() { super.onResume(); if (!busy) build() }

    private fun build() {
        content.removeAllViews()
        boxes.clear()
        content.addView(Ui.text(this, "DroidCollector", 24f, Ui.TEXT, true))
        content.addView(Ui.text(this, "Exports logs, system state and APKs to ONE zip file that you choose where to save. " +
            "Nothing is uploaded. The zip contains personal data (app list, accounts list, logs): keep it safe.", 13f, Ui.MUTED))

        val cap = capabilities(this)
        val capCard = Ui.card(this)
        capCard.addView(Ui.text(this, "Access level", 16f, Ui.TEXT, true))
        fun line(k: String, label: String, hint: String) {
            val ok = cap.optBoolean(k)
            capCard.addView(Ui.text(this, (if (ok) "✔ " else "✖ ") + label + if (ok) "" else " – $hint", 13f,
                if (ok) 0xFF30A46C.toInt() else Ui.sevColor(org.droidsuite.core.Severity.MEDIUM)))
        }
        line("READ_LOGS", "All-app logcat", "grant via adb (below)")
        line("DUMP", "dumpsys system services", "grant via adb (below)")
        line("USAGE_ACCESS", "Usage & network history", "tap 'Usage access'")
        line("SENTINEL_REPORT", "DroidSentinel report", "install Sentinel first, same signing key")
        capCard.addView(Ui.text(this, "\nOne-time setup from a computer (USB debugging on):\n$adbCmds", 12f, Ui.ACCENT).apply { setTextIsSelectable(true) })
        capCard.addView(Ui.hbox(this).apply {
            addView(Ui.weighted(Ui.button(this@MainActivity, "Copy adb commands") {
                getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("adb", adbCmds))
            }))
            addView(Ui.weighted(Ui.button(this@MainActivity, "Usage access") { startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) }))
        })
        content.addView(capCard)

        content.addView(Ui.text(this, "What to collect", 16f, Ui.TEXT, true))
        val user = estimateUserApks()
        Section.values().forEach { s ->
            val cb = CheckBox(this).apply {
                text = "${s.title}" + if (s == Section.APKS_USER) "  (~${Util.humanBytes(user)})" else ""
                setTextColor(Ui.TEXT); isChecked = s.default
            }
            boxes[s] = cb
            content.addView(cb)
            content.addView(Ui.text(this, "      ${s.detail}", 11f, Ui.MUTED))
        }
        status = Ui.text(this, "", 14f, Ui.ACCENT)
        content.addView(Ui.button(this, "Collect…") { confirm() })
        content.addView(status)
    }

    private fun estimateUserApks(): Long = try {
        @Suppress("DEPRECATION")
        packageManager.getInstalledApplications(0).filter { it.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM == 0 }
            .sumOf { ai -> (listOfNotNull(ai.sourceDir) + (ai.splitSourceDirs?.toList() ?: emptyList())).sumOf { File(it).length() } }
    } catch (_: Exception) { 0L }

    private fun selected() = boxes.filter { it.value.isChecked }.keys

    /** Explicit user validation before anything is read. */
    private fun confirm() {
        if (busy) return
        val sel = selected()
        if (sel.isEmpty()) return
        AlertDialog.Builder(this)
            .setTitle("Collect forensic data?")
            .setMessage(
                "The following will be read and written into a zip you choose:\n\n" +
                    sel.joinToString("\n") { "• ${it.title}" } +
                    "\n\nThe archive can contain: list of installed apps, account names, Wi-Fi/network configuration, " +
                    "system logs (may include messages, URLs, locations), usage history and app files.\n\n" +
                    "Nothing leaves the phone. On Android 13+ the system will additionally ask you to allow log access."
            )
            .setNegativeButton("Cancel", null)
            .setPositiveButton("I agree – choose destination") { _, _ ->
                val name = "droidcollect_${android.os.Build.MODEL.replace(' ', '_')}_" +
                    SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date()) + ".zip"
                startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                    .setType("application/zip").putExtra(Intent.EXTRA_TITLE, name), REQ_DEST)
            }.show()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQ_DEST || resultCode != RESULT_OK) return
        val uri = data?.data ?: return
        run(uri)
    }

    private fun run(uri: Uri) {
        busy = true
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val sel = selected()
        Thread {
            val t0 = System.currentTimeMillis()
            val msg = try {
                val s = Collector(this, sel) { p -> runOnUiThread { status.text = p } }.run(uri)
                val files = s.getJSONArray("files").length()
                "✔ Done in ${(System.currentTimeMillis() - t0) / 1000}s – $files files, ${Util.humanBytes(s.optLong("totalBytes"))} (uncompressed).\n" +
                    "Copy the zip to your computer and run:\n  python3 -m droidtriage <zip> -o report/"
            } catch (e: Exception) {
                "✖ Failed: ${e.message}"
            }
            runOnUiThread {
                busy = false
                window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                status.text = msg
                content.addView(Ui.button(this, "Share zip…") {
                    startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("application/zip")
                        .putExtra(Intent.EXTRA_STREAM, uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION), "Share"))
                })
            }
        }.start()
    }
}

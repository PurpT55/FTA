package org.droidsuite.sentinel

import android.content.Context
import org.droidsuite.core.Category
import org.droidsuite.core.Severity
import org.droidsuite.core.VtVerdict
import org.json.JSONObject
import java.io.DataOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/**
 * VirusTotal v3 client.
 *
 * PRIVACY CONTRACT: [lookupHash] and [lookupDomain] only send a SHA-256 / domain name.
 * [uploadFile] is the ONLY method that sends file content and must only be called
 * from an explicit, confirmed user action (see MainActivity.confirmUpload).
 *
 * Free public API limits: 4 requests/minute, 500/day. Calls are spaced 16 s apart.
 */
class VtClient(private val ctx: Context) {
    class QuotaException(msg: String) : Exception(msg)

    private val store = Store.get(ctx)
    private val base = "https://www.virustotal.com/api/v3"

    companion object {
        private val lock = Object()
        private var lastCall = 0L
        private const val SPACING_MS = 16_000L
        private const val DAILY_LIMIT = 480
        val executor = Executors.newSingleThreadExecutor()
        @Volatile var queued = 0
    }

    val configured get() = store.vtKey.isNotBlank()

    private fun throttle() {
        val day = SimpleDateFormat("yyyyMMdd", Locale.US).format(Date())
        val p = store.prefs
        val used = if (p.getString("vt_day", "") == day) p.getInt("vt_used", 0) else 0
        if (used >= DAILY_LIMIT) throw QuotaException("Daily VirusTotal quota reached ($used)")
        synchronized(lock) {
            val wait = lastCall + SPACING_MS - System.currentTimeMillis()
            if (wait > 0) Thread.sleep(wait)
            lastCall = System.currentTimeMillis()
        }
        p.edit().putString("vt_day", day).putInt("vt_used", used + 1).apply()
    }

    private fun get(path: String): Pair<Int, String> {
        throttle()
        val c = URL("$base$path").openConnection() as HttpURLConnection
        c.setRequestProperty("x-apikey", store.vtKey)
        c.setRequestProperty("accept", "application/json")
        c.connectTimeout = 15_000; c.readTimeout = 30_000
        val code = c.responseCode
        val body = (if (code in 200..299) c.inputStream else c.errorStream)?.bufferedReader()?.readText() ?: ""
        if (code == 429) throw QuotaException("VirusTotal rate limit (429)")
        if (code == 401) throw QuotaException("VirusTotal API key rejected (401)")
        return Pair(code, body)
    }

    fun lookupHash(sha256: String): VtVerdict {
        val (code, body) = get("/files/$sha256")
        val now = System.currentTimeMillis()
        if (code == 404) return VtVerdict(sha256, -1, 0, null, now)
        if (code !in 200..299) throw Exception("VirusTotal HTTP $code")
        val attr = JSONObject(body).getJSONObject("data").getJSONObject("attributes")
        val stats = attr.optJSONObject("last_analysis_stats") ?: JSONObject()
        var total = 0
        stats.keys().forEach { total += stats.optInt(it) }
        val label = attr.optJSONObject("popular_threat_classification")?.optString("suggested_threat_label")
            ?.takeIf { it.isNotEmpty() } ?: attr.optString("meaningful_name").takeIf { it.isNotEmpty() }
        return VtVerdict(sha256, stats.optInt("malicious"), total, label, now)
    }

    /** Returns (malicious, total) for a domain. */
    fun lookupDomain(domain: String): Pair<Int, Int> {
        val (code, body) = get("/domains/$domain")
        if (code == 404) return Pair(-1, 0)
        if (code !in 200..299) throw Exception("VirusTotal HTTP $code")
        val stats = JSONObject(body).getJSONObject("data").getJSONObject("attributes").optJSONObject("last_analysis_stats") ?: JSONObject()
        var total = 0
        stats.keys().forEach { total += stats.optInt(it) }
        return Pair(stats.optInt("malicious"), total)
    }

    /** USER-CONFIRMED ONLY. Uploads the APK file. Returns the analysis id. */
    fun uploadFile(file: File): String {
        throttle()
        val target = if (file.length() > 32L * 1024 * 1024) {
            val (code, body) = get("/files/upload_url")
            if (code !in 200..299) throw Exception("upload_url HTTP $code")
            JSONObject(body).getString("data")
        } else "$base/files"
        val boundary = "----droidsentinel${System.nanoTime()}"
        val c = URL(target).openConnection() as HttpURLConnection
        c.doOutput = true
        c.requestMethod = "POST"
        c.setChunkedStreamingMode(1 shl 16)
        c.setRequestProperty("x-apikey", store.vtKey)
        c.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
        c.connectTimeout = 30_000; c.readTimeout = 300_000
        DataOutputStream(c.outputStream).use { out ->
            out.writeBytes("--$boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"${file.name}\"\r\n")
            out.writeBytes("Content-Type: application/octet-stream\r\n\r\n")
            file.inputStream().use { it.copyTo(out, 1 shl 16) }
            out.writeBytes("\r\n--$boundary--\r\n")
        }
        val code = c.responseCode
        val body = (if (code in 200..299) c.inputStream else c.errorStream)?.bufferedReader()?.readText() ?: ""
        if (code !in 200..299) throw Exception("Upload failed HTTP $code: ${body.take(200)}")
        return JSONObject(body).getJSONObject("data").getString("id")
    }

    /** Queue background hash lookups (skips hashes checked in the last 7 days). */
    fun enqueue(items: List<Pair<String, String>>, onDone: (() -> Unit)? = null) {
        if (!configured) return
        val cache = store.vtAll()
        val fresh = System.currentTimeMillis() - 7L * 86_400_000L
        val todo = items.filter { (_, h) -> (cache[h]?.checkedAt ?: 0) < fresh }.distinctBy { it.second }
        queued += todo.size
        executor.execute {
            for ((pkg, h) in todo) {
                try {
                    val v = lookupHash(h)
                    store.putVt(v, pkg)
                    if (v.positives > 0) {
                        val sev = if (v.positives >= 3) Severity.CRITICAL else Severity.MEDIUM
                        store.addEvent(Event(System.currentTimeMillis(), sev, Category.MALWARE, pkg, "vt",
                            "VirusTotal: ${v.positives}/${v.total} detections", v.label ?: h))
                        Notifier.alert(ctx, "VirusTotal detection: $pkg", "${v.positives}/${v.total} engines – ${v.label ?: ""}")
                    }
                } catch (e: QuotaException) {
                    store.addEvent(Event(System.currentTimeMillis(), Severity.INFO, Category.UNKNOWN, null, "vt", "VirusTotal paused", e.message ?: ""))
                    queued = 0
                    break
                } catch (_: Exception) {
                } finally {
                    if (queued > 0) queued--
                }
            }
            onDone?.invoke()
        }
    }
}

package org.droidsuite.core

import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.TimeUnit

object Util {
    fun hex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) sb.append(String.format("%02x", b))
        return sb.toString()
    }

    fun digest(algo: String, data: ByteArray): String =
        hex(MessageDigest.getInstance(algo).digest(data))

    fun sha256(file: File): String? = try {
        file.inputStream().use { sha256(it) }
    } catch (e: Exception) {
        null
    }

    fun sha256(input: InputStream): String {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(1 shl 16)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
        }
        return hex(md.digest())
    }

    fun iso(ts: Long): String {
        val f = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        f.timeZone = TimeZone.getTimeZone("UTC")
        return f.format(Date(ts))
    }

    fun local(ts: Long): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(ts))

    fun humanBytes(b: Long): String {
        if (b < 1024) return "$b B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var v = b.toDouble() / 1024
        var i = 0
        while (v >= 1024 && i < units.size - 1) { v /= 1024; i++ }
        return String.format(Locale.US, "%.1f %s", v, units[i])
    }

    /**
     * Runs a command as this app's own UID (no root). Many commands fail or
     * return partial data without adb-granted permissions; the error text is
     * returned so the caller can record it instead of silently dropping it.
     */
    fun exec(cmd: List<String>, timeoutSec: Long = 20, maxBytes: Int = 8 shl 20): ExecResult {
        return try {
            val p = ProcessBuilder(cmd).redirectErrorStream(true).start()
            val out = java.io.ByteArrayOutputStream()
            val reader = Thread {
                try {
                    val buf = ByteArray(1 shl 16)
                    val ins = p.inputStream
                    while (true) {
                        val n = ins.read(buf)
                        if (n < 0) break
                        if (out.size() < maxBytes) out.write(buf, 0, minOf(n, maxBytes - out.size()))
                    }
                } catch (_: Exception) {
                }
            }
            reader.start()
            val finished = p.waitFor(timeoutSec, TimeUnit.SECONDS)
            if (!finished) p.destroy()
            reader.join(2000)
            ExecResult(if (finished) p.exitValue() else -1, out.toByteArray(), !finished)
        } catch (e: Exception) {
            ExecResult(-2, ("exec failed: ${e.message}").toByteArray(), false)
        }
    }

    fun getprop(name: String): String =
        String(exec(listOf("getprop", name), 5).output).trim()
}

class ExecResult(val code: Int, val output: ByteArray, val timedOut: Boolean) {
    val text: String get() = String(output)
}

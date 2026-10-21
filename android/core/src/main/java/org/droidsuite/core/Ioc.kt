package org.droidsuite.core

import java.io.File

/**
 * Indicator-of-compromise database. Reads the stalkerware-indicators `ioc.yaml`
 * format (https://github.com/AssoEchap/stalkerware-indicators) with a small
 * line parser, plus plain text lists (one package / domain / hash per line).
 */
class IocDb {
    class Entry(val family: String, val kind: String)

    val packages = HashMap<String, Entry>()
    val certSha1 = HashMap<String, Entry>()
    val domains = HashMap<String, Entry>()
    val ips = HashMap<String, Entry>()
    val hashes = HashMap<String, Entry>()

    val size get() = packages.size + certSha1.size + domains.size + ips.size + hashes.size

    fun loadDir(dir: File) {
        dir.listFiles()?.sortedBy { it.name }?.forEach { f ->
            try {
                if (f.name.endsWith(".yaml") || f.name.endsWith(".yml")) parseYaml(f.readLines())
                else if (f.name.endsWith(".txt")) parseText(f.readLines(), f.nameWithoutExtension)
            } catch (_: Exception) { }
        }
    }

    fun parseYaml(lines: List<String>) {
        var family = "unknown"
        var kind = "stalkerware"
        var key = ""
        for (raw in lines) {
            if (raw.isBlank() || raw.trimStart().startsWith("#")) continue
            val indent = raw.length - raw.trimStart().length
            val line = raw.trim()
            if (indent == 0 && line.startsWith("- name:")) {
                family = line.removePrefix("- name:").trim().trim('"', '\''); key = ""; continue
            }
            if (!line.startsWith("-") && line.contains(':')) {
                val k = line.substringBefore(':').trim()
                val v = line.substringAfter(':').trim()
                if (k == "type" && v.isNotEmpty()) kind = v
                key = k
                continue
            }
            if (line.startsWith("- ")) {
                val v = line.removePrefix("- ").trim().trim('"', '\'')
                val e = Entry(family, kind)
                when (key) {
                    "packages" -> packages[v] = e
                    "certificates" -> certSha1[v.lowercase()] = e
                    "websites", "domains", "distribution" ->
                        if (v.matches(Regex("""\d+\.\d+\.\d+\.\d+"""))) ips[v] = e else domains[v.lowercase()] = e
                    "ips", "ip" -> ips[v] = e
                    "sha256" -> hashes[v.lowercase()] = e
                }
            }
        }
    }

    /** Plain lists: lines like `package:com.x`, `domain:x.com`, `sha256:...`, `cert:...`, `ip:...`. */
    fun parseText(lines: List<String>, family: String) {
        for (l in lines) {
            val t = l.trim()
            if (t.isEmpty() || t.startsWith("#")) continue
            val type = t.substringBefore(':', "").lowercase()
            val v = t.substringAfter(':').trim()
            val e = Entry(family, "custom")
            when (type) {
                "package" -> packages[v] = e
                "domain" -> domains[v.lowercase()] = e
                "ip" -> ips[v] = e
                "sha256" -> hashes[v.lowercase()] = e
                "cert", "cert_sha1" -> certSha1[v.lowercase()] = e
            }
        }
    }

    /** Suffix match so `a.b.evil.com` hits `evil.com`. */
    fun matchDomain(domain: String): Entry? {
        var d = domain.lowercase().trimEnd('.')
        while (true) {
            domains[d]?.let { return it }
            val i = d.indexOf('.')
            if (i < 0) return null
            d = d.substring(i + 1)
        }
    }
}

package org.droidsuite.sentinel

import org.droidsuite.core.IocDb
import kotlin.math.ln

/**
 * Offline heuristics for DNS names. Returns a short flag string or null.
 * Mirrored by analyzer/droidtriage/network.py `classify` (tests/test_parity.py checks the lists stay aligned).
 */
object DomainIntel {
    private val DYNDNS = listOf(
        "duckdns.org", "no-ip.com", "no-ip.org", "ddns.net", "hopto.org", "zapto.org", "sytes.net",
        "servebeer.com", "dynu.net", "freedns.afraid.org", "mooo.com", "dyndns.org", "3utilities.com",
    )
    private val TUNNELS = listOf(
        "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "serveo.net", "loca.lt",
        "localtunnel.me", "pagekite.me", "portmap.io", "bore.pub",
    )
    private val PASTE_EXFIL = listOf(
        "pastebin.com", "paste.ee", "hastebin.com", "transfer.sh", "anonfiles.com", "file.io",
        "webhook.site", "requestbin.net", "pipedream.net", "discord.com/api/webhooks",
    )
    private val TRACKERS = listOf(
        "doubleclick.net", "googlesyndication.com", "app-measurement.com", "graph.facebook.com",
        "appsflyer.com", "adjust.com", "branch.io", "onesignal.com", "applovin.com", "unityads.unity3d.com",
        "inmobi.com", "chartboost.com", "ironsrc.mobi", "supersonicads.com", "mopub.com", "vungle.com",
        "startappservice.com", "mintegral.com", "pangle.io", "bytedance.com", "amplitude.com", "mixpanel.com",
        "segment.io", "kochava.com", "flurry.com", "crashlytics.com", "bugsnag.com", "sentry.io",
    )
    private val RISKY_TLDS = setOf("top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "zip", "mov", "cyou", "rest", "su", "icu")
    private val TELEGRAM_APPS = setOf("org.telegram.messenger", "org.telegram.messenger.web", "org.thunderdog.challegram", "org.telegram.plus")

    fun classify(domain: String, pkg: String, iocs: IocDb?): String? {
        val d = domain.lowercase().trimEnd('.')
        iocs?.matchDomain(d)?.let { return "IOC:${it.family}" }
        fun under(list: List<String>) = list.any { d == it || d.endsWith(".$it") }
        if (under(DYNDNS)) return "dynamic-dns"
        if (under(TUNNELS)) return "tunnel-service"
        if (under(PASTE_EXFIL)) return "paste/exfil-service"
        if (d == "api.telegram.org" && pkg !in TELEGRAM_APPS) return "telegram-bot-api"
        if (d.endsWith(".onion") || d.contains("tor2web")) return "tor"
        if (d.matches(Regex(""".*\d+[-.]\d+[-.]\d+[-.]\d+\.(nip\.io|sslip\.io|xip\.io)"""))) return "ip-in-dns"
        val tld = d.substringAfterLast('.')
        val label = d.split('.').let { if (it.size >= 2) it[it.size - 2] else it[0] }
        if (label.length >= 12 && entropy(label) > 3.4 && label.count { it in "aeiou" } * 5 < label.length) return "dga-like"
        if (tld in RISKY_TLDS) return "risky-tld"
        if (under(TRACKERS)) return "tracker"
        return null
    }

    fun isSevere(flag: String) = flag.startsWith("IOC:") || flag in setOf("dynamic-dns", "tunnel-service", "telegram-bot-api", "tor", "dga-like", "paste/exfil-service")

    private fun entropy(s: String): Double {
        val counts = s.groupingBy { it }.eachCount()
        return -counts.values.sumOf { val p = it.toDouble() / s.length; p * ln(p) / ln(2.0) }
    }
}

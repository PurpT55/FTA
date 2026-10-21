package org.droidsuite.sentinel

import android.content.ContentValues
import android.content.Context
import android.content.SharedPreferences
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import org.droidsuite.core.Category
import org.droidsuite.core.RiskEngine
import org.droidsuite.core.Severity
import org.droidsuite.core.VtVerdict
import org.json.JSONArray
import org.json.JSONObject

data class Event(
    val ts: Long, val severity: Severity, val category: Category, val pkg: String?,
    val type: String, val title: String, val detail: String,
)

data class DnsRow(val ts: Long, val pkg: String, val domain: String, val qtype: Int, val flag: String?)

/** SQLite event store + preferences. All methods are thread-safe through SQLiteDatabase locking. */
class Store private constructor(ctx: Context) : SQLiteOpenHelper(ctx, "sentinel.db", null, 1) {
    companion object {
        @Volatile private var inst: Store? = null
        fun get(ctx: Context): Store = inst ?: synchronized(this) {
            inst ?: Store(ctx.applicationContext).also { inst = it }
        }
        const val MAX_DNS_ROWS = 50_000
        const val MAX_EVENT_ROWS = 20_000
    }

    val prefs: SharedPreferences = ctx.getSharedPreferences("sentinel", Context.MODE_PRIVATE)

    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL("CREATE TABLE events(id INTEGER PRIMARY KEY, ts INTEGER, severity TEXT, category TEXT, pkg TEXT, type TEXT, title TEXT, detail TEXT)")
        db.execSQL("CREATE INDEX ev_ts ON events(ts)")
        db.execSQL("CREATE TABLE dns(id INTEGER PRIMARY KEY, ts INTEGER, pkg TEXT, domain TEXT, qtype INTEGER, flag TEXT)")
        db.execSQL("CREATE INDEX dns_ts ON dns(ts)")
        db.execSQL("CREATE TABLE traffic(id INTEGER PRIMARY KEY, ts INTEGER, uid INTEGER, pkg TEXT, rx INTEGER, tx INTEGER, screen_on INTEGER)")
        db.execSQL("CREATE TABLE vt(sha256 TEXT PRIMARY KEY, pkg TEXT, positives INTEGER, total INTEGER, label TEXT, ts INTEGER)")
        db.execSQL("CREATE TABLE baseline(pkg TEXT PRIMARY KEY, json TEXT)")
    }

    override fun onUpgrade(db: SQLiteDatabase, o: Int, n: Int) {}

    // ---------- preferences
    var vtKey: String
        get() = prefs.getString("vt_key", "") ?: ""
        set(v) = prefs.edit().putString("vt_key", v.trim()).apply()
    var autoVt: Boolean
        get() = prefs.getBoolean("auto_vt", true)
        set(v) = prefs.edit().putBoolean("auto_vt", v).apply()
    var monitorEnabled: Boolean
        get() = prefs.getBoolean("monitor", false)
        set(v) = prefs.edit().putBoolean("monitor", v).apply()
    var dnsEnabled: Boolean
        get() = prefs.getBoolean("dns", false)
        set(v) = prefs.edit().putBoolean("dns", v).apply()
    var trustedInstallers: Set<String>
        get() = prefs.getString("trusted", null)?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.toSet()
            ?: RiskEngine.DEFAULT_TRUSTED_INSTALLERS
        set(v) = prefs.edit().putString("trusted", v.joinToString(",")).apply()
    var bgUploadThresholdMb: Int
        get() = prefs.getInt("bg_mb", 5)
        set(v) = prefs.edit().putInt("bg_mb", v).apply()

    // ---------- events
    fun addEvent(e: Event) {
        writableDatabase.insert("events", null, ContentValues().apply {
            put("ts", e.ts); put("severity", e.severity.name); put("category", e.category.name)
            put("pkg", e.pkg); put("type", e.type); put("title", e.title); put("detail", e.detail)
        })
    }

    fun events(sinceMs: Long = 0, limit: Int = 500): List<Event> {
        val out = ArrayList<Event>()
        readableDatabase.rawQuery(
            "SELECT ts,severity,category,pkg,type,title,detail FROM events WHERE ts>=? ORDER BY ts DESC LIMIT $limit",
            arrayOf(sinceMs.toString())
        ).use { c ->
            while (c.moveToNext()) out += Event(
                c.getLong(0), Severity.valueOf(c.getString(1)), Category.valueOf(c.getString(2)),
                c.getString(3), c.getString(4), c.getString(5), c.getString(6) ?: ""
            )
        }
        return out
    }

    // ---------- dns
    fun addDns(r: DnsRow) {
        writableDatabase.insert("dns", null, ContentValues().apply {
            put("ts", r.ts); put("pkg", r.pkg); put("domain", r.domain); put("qtype", r.qtype); put("flag", r.flag)
        })
    }

    fun dns(limit: Int = 500, flaggedOnly: Boolean = false): List<DnsRow> {
        val out = ArrayList<DnsRow>()
        val where = if (flaggedOnly) "WHERE flag IS NOT NULL" else ""
        readableDatabase.rawQuery("SELECT ts,pkg,domain,qtype,flag FROM dns $where ORDER BY ts DESC LIMIT $limit", null).use { c ->
            while (c.moveToNext()) out += DnsRow(c.getLong(0), c.getString(1), c.getString(2), c.getInt(3), c.getString(4))
        }
        return out
    }

    /** Domain counts per app: pkg -> (domain -> count). */
    fun dnsSummary(): Map<String, Map<String, Int>> {
        val out = HashMap<String, HashMap<String, Int>>()
        readableDatabase.rawQuery("SELECT pkg, domain, COUNT(*) FROM dns GROUP BY pkg, domain", null).use { c ->
            while (c.moveToNext()) out.getOrPut(c.getString(0)) { HashMap() }[c.getString(1)] = c.getInt(2)
        }
        return out
    }

    fun knownDomainForPkg(pkg: String, domain: String): Boolean =
        readableDatabase.rawQuery("SELECT 1 FROM dns WHERE pkg=? AND domain=? LIMIT 1", arrayOf(pkg, domain)).use { it.moveToFirst() }

    // ---------- traffic
    fun addTraffic(ts: Long, uid: Int, pkg: String, rx: Long, tx: Long, screenOn: Boolean) {
        writableDatabase.insert("traffic", null, ContentValues().apply {
            put("ts", ts); put("uid", uid); put("pkg", pkg); put("rx", rx); put("tx", tx); put("screen_on", if (screenOn) 1 else 0)
        })
    }

    /** pkg -> (rx, tx, txWhileScreenOff) since [sinceMs]. */
    fun trafficSummary(sinceMs: Long): Map<String, LongArray> {
        val out = HashMap<String, LongArray>()
        readableDatabase.rawQuery(
            "SELECT pkg, SUM(rx), SUM(tx), SUM(CASE WHEN screen_on=0 THEN tx ELSE 0 END) FROM traffic WHERE ts>=? GROUP BY pkg",
            arrayOf(sinceMs.toString())
        ).use { c -> while (c.moveToNext()) out[c.getString(0)] = longArrayOf(c.getLong(1), c.getLong(2), c.getLong(3)) }
        return out
    }

    fun hasTrafficHistory(pkg: String): Boolean =
        readableDatabase.rawQuery("SELECT 1 FROM traffic WHERE pkg=? LIMIT 1", arrayOf(pkg)).use { it.moveToFirst() }

    // ---------- VirusTotal cache
    fun putVt(v: VtVerdict, pkg: String) {
        writableDatabase.insertWithOnConflict("vt", null, ContentValues().apply {
            put("sha256", v.sha256); put("pkg", pkg); put("positives", v.positives); put("total", v.total)
            put("label", v.label); put("ts", v.checkedAt)
        }, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun vtAll(): Map<String, VtVerdict> {
        val out = HashMap<String, VtVerdict>()
        readableDatabase.rawQuery("SELECT sha256,positives,total,label,ts FROM vt", null).use { c ->
            while (c.moveToNext()) out[c.getString(0)] = VtVerdict(c.getString(0), c.getInt(1), c.getInt(2), c.getString(3), c.getLong(4))
        }
        return out
    }

    // ---------- integrity baseline
    fun baseline(): Map<String, JSONObject> {
        val out = HashMap<String, JSONObject>()
        readableDatabase.rawQuery("SELECT pkg,json FROM baseline", null).use { c ->
            while (c.moveToNext()) out[c.getString(0)] = JSONObject(c.getString(1))
        }
        return out
    }

    fun putBaseline(pkg: String, o: JSONObject) {
        writableDatabase.insertWithOnConflict("baseline", null, ContentValues().apply {
            put("pkg", pkg); put("json", o.toString())
        }, SQLiteDatabase.CONFLICT_REPLACE)
    }

    fun removeBaseline(pkg: String) { writableDatabase.delete("baseline", "pkg=?", arrayOf(pkg)) }

    fun prune() {
        val db = writableDatabase
        db.execSQL("DELETE FROM dns WHERE id NOT IN (SELECT id FROM dns ORDER BY id DESC LIMIT $MAX_DNS_ROWS)")
        db.execSQL("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT $MAX_EVENT_ROWS)")
        db.execSQL("DELETE FROM traffic WHERE ts < ?", arrayOf(System.currentTimeMillis() - 30L * 86_400_000L))
    }

    fun exportJson(sinceMs: Long): JSONObject = JSONObject()
        .put("events", JSONArray(events(sinceMs, 5000).map {
            JSONObject().put("ts", it.ts).put("severity", it.severity.name).put("category", it.category.name)
                .put("package", it.pkg ?: JSONObject.NULL).put("type", it.type).put("title", it.title).put("detail", it.detail)
        }))
        .put("dns", JSONArray(dns(20_000).map {
            JSONObject().put("ts", it.ts).put("package", it.pkg).put("domain", it.domain).put("qtype", it.qtype)
                .put("flag", it.flag ?: JSONObject.NULL)
        }))
        .put("traffic", JSONObject().apply {
            trafficSummary(sinceMs).forEach { (k, v) ->
                put(k, JSONObject().put("rx", v[0]).put("tx", v[1]).put("txScreenOff", v[2]))
            }
        })
        .put("virustotal", JSONArray(vtAll().values.map {
            JSONObject().put("sha256", it.sha256).put("positives", it.positives).put("total", it.total)
                .put("label", it.label ?: JSONObject.NULL).put("checkedAt", it.checkedAt)
        }))
}

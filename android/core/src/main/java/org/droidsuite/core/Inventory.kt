package org.droidsuite.core

import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.File
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/** Which APKs get a SHA-256 during a scan. Hashing every system APK costs minutes on first run. */
enum class HashPolicy {
    /** Never hash (fast inventory). */
    NONE,
    /** User apps + updated system apps: everything that can change after the factory image. Default. */
    USER_AND_UPDATED,
    /** Every package, including read-only system APKs (Collector "all system APKs"). */
    ALL;

    fun applies(system: Boolean, updatedSystem: Boolean): Boolean = when (this) {
        NONE -> false
        ALL -> true
        USER_AND_UPDATED -> !system || updatedSystem
    }
}

/**
 * Enumerates installed packages through the public PackageManager API.
 * Requires QUERY_ALL_PACKAGES on Android 11+ to see everything.
 * APK hashes are cached in `files/apk_hash_cache.json` keyed by path|size|mtime.
 */
class Inventory(private val ctx: Context) {
    private val pm: PackageManager = ctx.packageManager
    private val hashCacheFile = File(ctx.filesDir, "apk_hash_cache.json")
    private val hashCache: JSONObject = try {
        JSONObject(hashCacheFile.readText())
    } catch (_: Exception) {
        JSONObject()
    }

    @Suppress("DEPRECATION")
    private val baseFlags: Int = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
        PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or PackageManager.GET_PERMISSIONS or
        (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES) or
        PackageManager.MATCH_DISABLED_COMPONENTS

    @Suppress("DEPRECATION")
    fun packageNames(): List<String> =
        pm.getInstalledPackages(PackageManager.MATCH_DISABLED_COMPONENTS).map { it.packageName }.sorted()

    private fun launcherPackages(): Set<String> {
        val i = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION")
        return pm.queryIntentActivities(i, PackageManager.MATCH_DISABLED_COMPONENTS)
            .map { it.activityInfo.packageName }.toSet()
    }

    /** Full scan; [policy] decides which base.apk files are hashed (cached hashes are always reused). */
    fun scan(policy: HashPolicy = HashPolicy.USER_AND_UPDATED, progress: ((Int, Int) -> Unit)? = null): List<AppRecord> {
        val names = packageNames()
        val launchers = launcherPackages()
        val out = ArrayList<AppRecord>(names.size)
        names.forEachIndexed { idx, name ->
            progress?.invoke(idx, names.size)
            record(name, launchers, policy)?.let { out.add(it) }
        }
        if (policy != HashPolicy.NONE) saveHashCache()
        return out
    }

    /** Re-read one package (e.g. after a PACKAGE_REPLACED broadcast). */
    fun single(pkg: String, policy: HashPolicy = HashPolicy.USER_AND_UPDATED): AppRecord? {
        val r = record(pkg, launcherPackages(), policy)
        if (policy != HashPolicy.NONE) saveHashCache()
        return r
    }

    @Suppress("DEPRECATION")
    private fun info(pkg: String): PackageInfo? = try {
        pm.getPackageInfo(pkg, baseFlags)
    } catch (e: Exception) {
        // Some packages exceed the binder limit with all component flags: retry lighter.
        try {
            pm.getPackageInfo(pkg, baseFlags and PackageManager.GET_PROVIDERS.inv() and PackageManager.GET_RECEIVERS.inv())
        } catch (_: Exception) {
            null
        }
    }

    private fun record(pkg: String, launchers: Set<String>, policy: HashPolicy): AppRecord? {
        val pi = info(pkg) ?: return null
        val ai = pi.applicationInfo ?: return null
        val (installer, initiating) = installers(pkg)
        val (certs, history) = signingCerts(pi)
        val paths = buildList {
            ai.sourceDir?.let { add(it) }
            ai.splitSourceDirs?.let { addAll(it) }
        }
        val size = paths.sumOf { File(it).length() }
        val requested = pi.requestedPermissions?.toList() ?: emptyList()
        val granted = HashSet<String>()
        pi.requestedPermissions?.forEachIndexed { i, p ->
            val f = pi.requestedPermissionsFlags?.getOrNull(i) ?: 0
            if (f and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0) granted.add(p)
        }
        val comps = ArrayList<ComponentInfo>()
        pi.activities?.forEach {
            comps.add(
                ComponentInfo(
                    "activity", it.name, it.exported, it.permission, it.taskAffinity, it.launchMode,
                    it.flags and ActivityInfo.FLAG_ALLOW_TASK_REPARENTING != 0,
                )
            )
        }
        pi.services?.forEach { comps.add(ComponentInfo("service", it.name, it.exported, it.permission)) }
        pi.receivers?.forEach { comps.add(ComponentInfo("receiver", it.name, it.exported, it.permission)) }
        pi.providers?.forEach {
            comps.add(ComponentInfo("provider", it.name, it.exported, it.readPermission ?: it.writePermission, authority = it.authority))
        }
        val libs = try {
            ai.nativeLibraryDir?.let { d -> File(d).list()?.sorted() } ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
        val versionCode = if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode else {
            @Suppress("DEPRECATION") pi.versionCode.toLong()
        }
        val isSystem = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0
        val isUpdated = ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
        val sha = if (policy.applies(isSystem, isUpdated)) hashCached(ai.sourceDir) else cachedOnly(ai.sourceDir)
        return AppRecord(
            pkg = pkg,
            label = try { ai.loadLabel(pm).toString() } catch (_: Exception) { pkg },
            uid = ai.uid,
            versionCode = versionCode,
            versionName = pi.versionName,
            installer = installer,
            initiatingInstaller = initiating,
            firstInstall = pi.firstInstallTime,
            lastUpdate = pi.lastUpdateTime,
            system = isSystem,
            updatedSystem = isUpdated,
            enabled = ai.enabled,
            hasLauncher = pkg in launchers,
            debuggable = ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
            cleartext = ai.flags and ApplicationInfo.FLAG_USES_CLEARTEXT_TRAFFIC != 0,
            targetSdk = ai.targetSdkVersion,
            sharedUserId = pi.sharedUserId,
            apkPaths = paths,
            apkSize = size,
            apkSha256 = sha,
            certSha256 = certs.map { Util.digest("SHA-256", it) },
            certSha1 = certs.map { Util.digest("SHA-1", it) },
            certSubjects = certs.mapNotNull { subject(it) },
            certHistorySha256 = history.map { Util.digest("SHA-256", it) },
            requested = requested,
            granted = granted,
            components = comps,
            nativeLibs = libs,
        )
    }

    private fun installers(pkg: String): Pair<String?, String?> = try {
        if (Build.VERSION.SDK_INT >= 30) {
            val s = pm.getInstallSourceInfo(pkg)
            Pair(s.installingPackageName, s.initiatingPackageName)
        } else {
            @Suppress("DEPRECATION")
            Pair(pm.getInstallerPackageName(pkg), null)
        }
    } catch (_: Exception) {
        Pair(null, null)
    }

    /** Returns (current signer certs DER, rotation history DER). */
    private fun signingCerts(pi: PackageInfo): Pair<List<ByteArray>, List<ByteArray>> {
        if (Build.VERSION.SDK_INT >= 28) {
            val si = pi.signingInfo ?: return Pair(emptyList(), emptyList())
            val current: Array<Signature>? = si.apkContentsSigners
            val history: Array<Signature>? = if (si.hasMultipleSigners()) null else si.signingCertificateHistory
            return Pair(current?.map { it.toByteArray() } ?: emptyList(), history?.map { it.toByteArray() } ?: emptyList())
        }
        @Suppress("DEPRECATION")
        val sigs = pi.signatures?.map { it.toByteArray() } ?: emptyList()
        return Pair(sigs, emptyList())
    }

    private fun subject(der: ByteArray): String? = try {
        val c = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        c.subjectX500Principal.name
    } catch (_: Exception) {
        null
    }

    private fun cacheKey(path: String): String {
        val f = File(path)
        return "$path|${f.length()}|${f.lastModified()}"
    }

    private fun cachedOnly(path: String?): String? =
        path?.let { hashCache.optString(cacheKey(it)).ifEmpty { null } }

    private fun hashCached(path: String?): String? {
        if (path == null) return null
        val key = cacheKey(path)
        hashCache.optString(key).takeIf { it.isNotEmpty() }?.let { return it }
        val h = Util.sha256(File(path)) ?: return null
        hashCache.put(key, h)
        return h
    }

    private fun saveHashCache() {
        try { hashCacheFile.writeText(hashCache.toString()) } catch (_: Exception) { }
    }
}

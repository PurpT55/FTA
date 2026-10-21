package org.droidsuite.sentinel

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor

/**
 * Read-only report endpoint for the Collector app:
 *   content://org.droidsuite.sentinel.report/report.json
 * Protected by a signature permission, so only apps signed with the suite key can read it.
 */
class ReportProvider : ContentProvider() {
    override fun onCreate() = true

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        val ctx = context ?: return null
        val pipe = ParcelFileDescriptor.createPipe()
        Thread {
            ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]).use { out ->
                try {
                    val r = Scanner.last ?: Scanner.scan(ctx)
                    out.write(Scanner.reportJson(ctx, r).toString(1).toByteArray())
                } catch (e: Exception) {
                    out.write("{\"error\":\"${e.javaClass.simpleName}\"}".toByteArray())
                }
            }
        }.start()
        return pipe[0]
    }

    override fun getType(uri: Uri) = "application/json"
    override fun query(u: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? = null
    override fun insert(u: Uri, v: ContentValues?): Uri? = null
    override fun delete(u: Uri, s: String?, a: Array<String>?) = 0
    override fun update(u: Uri, v: ContentValues?, s: String?, a: Array<String>?) = 0
}

package com.alex193a.rootmypixel.utils

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/**
 * Installs the companion APKs bundled in the app's assets so the user does
 * not have to hunt for release/nightly download links (the ReSukiSU manager
 * is published through GitHub Actions artifacts that expire).
 *
 * The APK is copied out of the APK container into filesDir/companions and
 * handed to the system package installer through the app's FileProvider
 * ("${applicationId}.provider", files-path ".", already used for log export).
 */
object CompanionApks {
    const val SHIZUKU_ASSET = "companions/shizuku-v13.6.0.apk"
    const val SHIZUKU_FILE = "shizuku-v13.6.0.apk"
    const val RESUKISU_ASSET = "companions/resukisu-v4.2.0-rc3-arm64.apk"
    const val RESUKISU_FILE = "resukisu-v4.2.0-rc3-arm64.apk"

    fun installShizuku(context: Context) {
        installAsset(context, SHIZUKU_ASSET, SHIZUKU_FILE)
    }

    fun installResukiSu(context: Context) {
        installAsset(context, RESUKISU_ASSET, RESUKISU_FILE)
    }

    private fun installAsset(context: Context, assetName: String, displayName: String) {
        val dir = File(context.filesDir, "companions").apply { mkdirs() }
        val destination = File(dir, displayName)
        context.assets.open(assetName).use { input ->
            destination.outputStream().use { output -> input.copyTo(output) }
        }
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.provider",
            destination,
        )
        val intent = Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
            setDataAndType(uri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    }
}

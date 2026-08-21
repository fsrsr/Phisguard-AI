package com.phishguard.ai.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.graphics.drawable.Drawable
import android.os.Build
import android.util.Log

/**
 * Auto-detect installed messaging/social/browser apps pada HP user.
 *
 * Menggunakan PackageManager + ApplicationInfo.category untuk
 * menemukan app yang relevan untuk di-monitor.
 *
 * Contoh penggunaan:
 *   val detector = InstalledAppDetector(context)
 *   val apps = detector.detectApps()
 *   // Tampilkan di RecyclerView
 */
class InstalledAppDetector(private val context: Context) {

    private val TAG = "InstalledAppDetector"

    // Default apps yang sudah hardcoded di UI — jangan duplikat
    private val defaultApps = setOf(
        "com.android.chrome",
        "com.whatsapp",
        "org.telegram.messenger",
        "com.facebook.orca",
        "com.instagram.android",
        "com.android.mms"
    )

    // Known messaging/social/browser package names (fallback untuk API < 26)
    private val knownTargetPackages = mapOf(
        // Messaging
        "com.viber.voip" to "Messaging",
        "jp.naver.line.android" to "Messaging",
        "com.snapchat.android" to "Messaging",
        "com.discord" to "Messaging",
        "org.thoughtcrime.securesms" to "Messaging",    // Signal
        "com.tencent.mm" to "Messaging",                 // WeChat
        "com.kakao.talk" to "Messaging",
        "com.imo.android.imoim" to "Messaging",
        // Social
        "com.twitter.android" to "Social",
        "com.tiktok.android" to "Social",               // TikTok (bisa ada DM phishing)
        "com.reddit.frontpage" to "Social",
        "com.linkedin.android" to "Social",
        "com.pinterest" to "Social",
        // Browser
        "org.mozilla.firefox" to "Browser",
        "com.opera.browser" to "Browser",
        "com.opera.mini.native" to "Browser",
        "com.brave.browser" to "Browser",
        "com.microsoft.emmx" to "Browser",               // Edge
        "com.UCMobile.intl" to "Browser",                 // UC Browser
        "com.sec.android.app.sbrowser" to "Browser",      // Samsung Internet
        // Email (bisa ada phishing)
        "com.google.android.gm" to "Email",               // Gmail
        "com.yahoo.mobile.client.android.mail" to "Email",
        "com.microsoft.office.outlook" to "Email"
    )

    data class DetectedApp(
        val packageName: String,
        val appName: String,
        val icon: Drawable?,
        val category: String   // "Messaging", "Social", "Browser", "Email"
    )

    /**
     * Scan HP untuk menemukan messaging/social/browser apps.
     * Mengembalikan list app yang ter-install dan belum ada di default list.
     */
    fun detectApps(): List<DetectedApp> {
        val pm = context.packageManager
        val installed = pm.getInstalledApplications(0)

        val detected = mutableListOf<DetectedApp>()

        for (app in installed) {
            // Skip default apps dan system apps yang tidak relevan
            if (app.packageName in defaultApps) continue

            val category = getAppCategory(app)
            if (category != null) {
                try {
                    detected.add(
                        DetectedApp(
                            packageName = app.packageName,
                            appName = pm.getApplicationLabel(app).toString(),
                            icon = pm.getApplicationIcon(app),
                            category = category
                        )
                    )
                } catch (e: Exception) {
                    Log.w(TAG, "Error getting app info for ${app.packageName}", e)
                }
            }
        }

        Log.d(TAG, "Detected ${detected.size} additional apps")
        return detected.sortedBy { it.category }
    }

    /**
     * Determine if the app is a target category.
     * Returns category label or null if not relevant.
     */
    private fun getAppCategory(app: ApplicationInfo): String? {
        // Method 1: Check known packages map
        val knownCategory = knownTargetPackages[app.packageName]
        if (knownCategory != null) return knownCategory

        // Method 2: Check ApplicationInfo.category (API 26+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return when (app.category) {
                ApplicationInfo.CATEGORY_SOCIAL -> "Social"
                ApplicationInfo.CATEGORY_NEWS -> "News"
                else -> null
            }
        }

        return null
    }
}

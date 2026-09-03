package com.phishguard.ai.data

import android.content.Context
import android.content.SharedPreferences

/**
 * SharedPreferences wrapper for app-wide settings.
 */
class AppPreferences(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("phishguard_prefs", Context.MODE_PRIVATE)

    // --- App Monitoring Selection ---
    var monitorWhatsApp: Boolean
        get() = prefs.getBoolean(KEY_WHATSAPP, false)
        set(value) = prefs.edit().putBoolean(KEY_WHATSAPP, value).apply()

    var monitorTelegram: Boolean
        get() = prefs.getBoolean(KEY_TELEGRAM, false)
        set(value) = prefs.edit().putBoolean(KEY_TELEGRAM, value).apply()

    var monitorFacebook: Boolean
        get() = prefs.getBoolean(KEY_FACEBOOK, false)
        set(value) = prefs.edit().putBoolean(KEY_FACEBOOK, value).apply()

    var monitorInstagram: Boolean
        get() = prefs.getBoolean(KEY_INSTAGRAM, false)
        set(value) = prefs.edit().putBoolean(KEY_INSTAGRAM, value).apply()

    var monitorChrome: Boolean
        get() = prefs.getBoolean(KEY_CHROME, true)
        set(value) = prefs.edit().putBoolean(KEY_CHROME, value).apply()

    // SMS is always on (default true, can't be turned off from UI)
    val monitorSms: Boolean get() = true

    // --- Settings ---
    var notificationsEnabled: Boolean
        get() = prefs.getBoolean(KEY_NOTIFICATIONS, true)
        set(value) = prefs.edit().putBoolean(KEY_NOTIFICATIONS, value).apply()

    var ttsEnabled: Boolean
        get() = prefs.getBoolean(KEY_TTS, false)
        set(value) = prefs.edit().putBoolean(KEY_TTS, value).apply()

    // --- Custom Monitored Apps (from auto-detect) ---

    /**
     * Set a custom app as monitored or not.
     */
    fun setCustomMonitoredApp(packageName: String, enabled: Boolean) {
        val apps = getCustomMonitoredApps().toMutableSet()
        if (enabled) {
            apps.add(packageName)
        } else {
            apps.remove(packageName)
        }
        prefs.edit().putStringSet(KEY_CUSTOM_APPS, apps).apply()
    }

    /**
     * Get all custom monitored app package names.
     */
    fun getCustomMonitoredApps(): Set<String> {
        return prefs.getStringSet(KEY_CUSTOM_APPS, emptySet()) ?: emptySet()
    }

    /**
     * Returns the complete list of package names to be monitored.
     * Includes both hardcoded default apps and user-added custom apps.
     */
    fun getMonitoredPackages(): Set<String> {
        val packages = mutableSetOf<String>()
        // 1. Browsers (force some major ones based on toggle, though we can just force them)
        if (monitorChrome) {
            packages.add("com.android.chrome")
            packages.add("com.sec.android.app.sbrowser") // Samsung Internet
            packages.add("org.mozilla.firefox")
            packages.add("com.opera.browser")
            packages.add("com.microsoft.emmx") // Edge
        }
        
        // 2. Default SMS apps (Always ON as per user request)
        packages.add("com.google.android.apps.messaging")
        packages.add("com.samsung.android.messaging")

        // 3. Social / Chat apps (Toggled)
        if (monitorWhatsApp) packages.add("com.whatsapp")
        if (monitorTelegram) packages.add("org.telegram.messenger")
        if (monitorFacebook) packages.add("com.facebook.orca")
        if (monitorInstagram) packages.add("com.instagram.android")
        
        // Add custom monitored apps from auto-detect
        packages.addAll(getCustomMonitoredApps())
        return packages
    }

    // --- Preference Change Listener ---

    /**
     * Register a listener for preference changes.
     * Used by PhishGuardService to dynamically update packageNames.
     */
    fun registerListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) {
        prefs.registerOnSharedPreferenceChangeListener(listener)
    }

    /**
     * Unregister a preference change listener.
     */
    fun unregisterListener(listener: SharedPreferences.OnSharedPreferenceChangeListener) {
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }

    companion object {
        private const val KEY_WHATSAPP = "monitor_whatsapp"
        private const val KEY_TELEGRAM = "monitor_telegram"
        private const val KEY_FACEBOOK = "monitor_facebook"
        private const val KEY_INSTAGRAM = "monitor_instagram"
        private const val KEY_CHROME = "monitor_chrome"
        private const val KEY_NOTIFICATIONS = "notifications"
        private const val KEY_TTS = "tts"
        private const val KEY_CUSTOM_APPS = "custom_monitored_apps"
    }
}

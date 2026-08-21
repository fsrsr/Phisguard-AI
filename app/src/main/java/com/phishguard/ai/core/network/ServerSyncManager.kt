package com.phishguard.ai.core.network

import android.content.Context
import android.util.Log
import com.phishguard.ai.data.db.PhishingDatabase
import com.phishguard.ai.data.db.PhishingUrl
import com.phishguard.ai.data.db.PhishingNumber
import com.google.gson.Gson
import com.google.gson.JsonParser
import kotlin.concurrent.thread

/**
 * Real Server Sync Manager
 * 
 * Sinkronisasi data phishing dengan:
 * 1. Firebase Firestore (primary, already implemented via FirebaseSyncManager)
 * 2. Custom API endpoint (optional, untuk n8n workflow atau custom backend)
 * 3. PhishTank API (public phishing database)
 */
class ServerSyncManager(private val context: Context) {

    private val TAG = "ServerSyncManager"
    private val apiClient = ApiClient()
    private val gson = Gson()

    // Configurable endpoints
    var customApiBaseUrl: String = ""  // Set via settings if needed
    private val phishTankApiUrl = "https://data.phishtank.com/data/online-valid.json"
    
    private val database: PhishingDatabase by lazy {
        PhishingDatabase.getInstance(context)
    }

    data class PhishTankEntry(
        val url: String,
        val phish_id: String,
        val phish_detail_url: String,
        val submission_time: String,
        val verified: String,
        val verification_time: String,
        val target: String
    )

    /**
     * Sync phishing URLs dari PhishTank (public database)
     * Rate limit: 1 hour antara sync
     */
    fun syncFromPhishTank(onComplete: (success: Boolean, count: Int) -> Unit) {
        Log.d(TAG, "Syncing from PhishTank...")
        
        val lastSync = getLastSyncTime("phishtank")
        val oneHourAgo = System.currentTimeMillis() - (60 * 60 * 1000)
        
        if (lastSync > oneHourAgo) {
            Log.d(TAG, "PhishTank sync skipped (synced recently)")
            onComplete(false, 0)
            return
        }
        
        apiClient.get(phishTankApiUrl) { success, response ->
            if (success && response != null) {
                thread {
                    try {
                        // Parse JSON response
                        val jsonArray = JsonParser.parseString(response).asJsonArray
                        var insertCount = 0
                        
                        // Limit to first 1000 entries to avoid DB bloat
                        database.phishingUrlDao().deleteBySource("phishtank")
                        jsonArray.take(1000).forEach { element ->
                            try {
                                val entry = gson.fromJson(element, PhishTankEntry::class.java)
                                
                                // Extract domain
                                val domain = entry.url.removePrefix("http://")
                                    .removePrefix("https://")
                                    .removePrefix("www.")
                                    .split("/").first()
                                
                                // Insert ke database
                                database.phishingUrlDao().insert(PhishingUrl(
                                    url = entry.url,
                                    domain = domain,
                                    reason = "PhishTank verified: ${entry.target}",
                                    source = "phishtank",
                                    confidence = 1.0f
                                ))
                                
                                insertCount++
                            } catch (e: Exception) {
                                Log.e(TAG, "Error parsing PhishTank entry", e)
                            }
                        }
                        
                        saveLastSyncTime("phishtank")
                        Log.d(TAG, "PhishTank sync complete: $insertCount URLs imported")
                        onComplete(true, insertCount)
                        
                    } catch (e: Exception) {
                        Log.e(TAG, "Error processing PhishTank data", e)
                        onComplete(false, 0)
                    }
                }
            } else {
                Log.e(TAG, "Failed to fetch from PhishTank")
                onComplete(false, 0)
            }
        }
    }

    /**
     * Sync dari OpenPhish (public feed, gratis tanpa API key).
     * Format: plain-text, 1 URL per baris. Cap 4000 biar DB tidak membengkak.
     */
    fun syncFromOpenPhish(onComplete: (success: Boolean, count: Int) -> Unit) {
        Log.d(TAG, "Syncing from OpenPhish feed...")
        val lastSync = getLastSyncTime("openphish")
        if (System.currentTimeMillis() - lastSync < 6 * 60 * 60 * 1000L) {
            Log.d(TAG, "OpenPhish sync skipped (synced recently)")
            onComplete(false, 0)
            return
        }

        apiClient.get("https://openphish.com/feed.txt",
            headers = mapOf("User-Agent" to "PhishGuard/1.0 (Android security app)")) { success, response ->
            if (success && response != null) {
                thread {
                    try {
                        val lines = response.lines()
                            .map { it.trim() }
                            .filter { it.startsWith("http://") || it.startsWith("https://") }
                            .distinct()
                            .take(4000)

                        var insertCount = 0
                        database.phishingUrlDao().deleteBySource("openphish")
                        lines.forEach { url ->
                            try {
                                database.phishingUrlDao().insert(PhishingUrl(
                                    url = url,
                                    domain = extractDomain(url),
                                    reason = "OpenPhish feed",
                                    source = "openphish",
                                    confidence = 0.92f
                                ))
                                insertCount++
                            } catch (e: Exception) {
                                Log.e(TAG, "skip entry $url", e)
                            }
                        }
                        saveLastSyncTime("openphish")
                        val total = database.phishingUrlDao().getCount()
                        Log.d(TAG, "OpenPhish sync: +$insertCount baru (total DB=$total)")
                        sendLogToUI("✅ Database phishing diupdate (+$insertCount dari OpenPhish).", "System", "SYSTEM")
                        onComplete(true, insertCount)
                    } catch (e: Exception) {
                        Log.e(TAG, "OpenPhish parse error", e)
                        onComplete(false, 0)
                    }
                }
            } else {
                Log.e(TAG, "OpenPhish fetch failed")
                onComplete(false, 0)
            }
        }
    }

    /**
     * Jalankan semua feed publik (OpenPhish + PhishTank) berurutan.
     */
    fun syncAllPublicFeeds(onComplete: (totalAdded: Int) -> Unit) {
        syncFromOpenPhish { _, openCount ->
            syncFromPhishTank { _, tankCount ->
                onComplete(openCount + tankCount)
            }
        }
    }

    private fun sendLogToUI(message: String, source: String, type: String) {
        try {
            val prefs = context.getSharedPreferences("activity_log", Context.MODE_PRIVATE)
            val existing = (prefs.getStringSet("logs", mutableSetOf()) ?: mutableSetOf()).toMutableSet()
            existing.add("${System.currentTimeMillis()}|$message|$source|$type")
            if (existing.size > 200) { // jaga ukuran
                existing.removeAll(existing.take(existing.size - 200))
            }
            prefs.edit().putStringSet("logs", existing).apply()
        } catch (e: Exception) {
            Log.e(TAG, "sendLogToUI error", e)
        }
    }

    /**
     * Sync dari custom API endpoint (n8n workflow)
     */
    fun syncFromCustomApi(onComplete: (success: Boolean, count: Int) -> Unit) {
        if (customApiBaseUrl.isEmpty()) {
            Log.d(TAG, "Custom API not configured")
            onComplete(false, 0)
            return
        }
        
        Log.d(TAG, "Syncing from custom API: $customApiBaseUrl")
        
        apiClient.get("$customApiBaseUrl/phishing-urls") { success, response ->
            if (success && response != null) {
                thread {
                    try {
                        val jsonArray = JsonParser.parseString(response).asJsonArray
                        var insertCount = 0
                        
                        jsonArray.forEach { element ->
                            val obj = element.asJsonObject
                            val url = obj.get("url").asString
                            val domain = obj.get("domain")?.asString ?: extractDomain(url)
                            val reason = obj.get("reason")?.asString ?: "Reported by community"
                            
                            database.phishingUrlDao().insert(PhishingUrl(
                                url = url,
                                domain = domain,
                                reason = reason,
                                source = "api",
                                confidence = 0.95f
                            ))
                            
                            insertCount++
                        }
                        
                        Log.d(TAG, "Custom API sync complete: $insertCount URLs")
                        onComplete(true, insertCount)
                        
                    } catch (e: Exception) {
                        Log.e(TAG, "Error processing custom API data", e)
                        onComplete(false, 0)
                    }
                }
            } else {
                onComplete(false, 0)
            }
        }
    }

    /**
     * Report phishing URL ke server (crowdsourcing)
     */
    fun reportPhishingUrl(url: String, source: String, reason: String, onComplete: (Boolean) -> Unit) {
        Log.d(TAG, "Reporting phishing URL: $url")
        
        // Simpan ke local DB dulu (selalu berhasil)
        thread {
            val domain = extractDomain(url)
            database.phishingUrlDao().insert(PhishingUrl(
                url = url,
                domain = domain,
                reason = reason,
                source = "user_report",
                confidence = 1.0f
            ))
        }
        
        // Kirim ke custom API jika configured
        if (customApiBaseUrl.isNotEmpty()) {
            val json = gson.toJson(mapOf(
                "url" to url,
                "source" to source,
                "reason" to reason,
                "timestamp" to System.currentTimeMillis(),
                "app_version" to "1.0"
            ))
            
            apiClient.post("$customApiBaseUrl/report-url", json) { success, _ ->
                Log.d(TAG, "Report to server: ${if (success) "success" else "failed"}")
                onComplete(success)
            }
        } else {
            // No server configured, local save is enough
            onComplete(true)
        }
    }

    /**
     * Report phishing number ke server
     */
    fun reportPhishingNumber(number: String, source: String, reason: String, onComplete: (Boolean) -> Unit) {
        Log.d(TAG, "Reporting phishing number: $number")
        
        // Simpan ke local DB
        thread {
            database.phishingNumberDao().insert(PhishingNumber(
                number = number,
                reason = reason,
                source = "user_report",
                confidence = 1.0f
            ))
        }
        
        // Kirim ke server jika configured
        if (customApiBaseUrl.isNotEmpty()) {
            val json = gson.toJson(mapOf(
                "number" to number,
                "source" to source,
                "reason" to reason,
                "timestamp" to System.currentTimeMillis()
            ))
            
            apiClient.post("$customApiBaseUrl/report-number", json) { success, _ ->
                onComplete(success)
            }
        } else {
            onComplete(true)
        }
    }

    /**
     * Check URL terhadap server database (real-time check)
     */
    fun checkUrlOnServer(url: String, callback: (found: Boolean, isThreat: Boolean, reason: String) -> Unit) {
        if (customApiBaseUrl.isEmpty()) {
            callback(false, false, "Server not configured")
            return
        }
        
        val encodedUrl = java.net.URLEncoder.encode(url, "UTF-8")
        apiClient.get("$customApiBaseUrl/check-url?url=$encodedUrl") { success, response ->
            if (success && response != null) {
                try {
                    val obj = JsonParser.parseString(response).asJsonObject
                    val found = obj.get("found").asBoolean
                    val isThreat = obj.get("is_threat").asBoolean
                    val reason = obj.get("reason")?.asString ?: "Unknown"
                    
                    callback(found, isThreat, reason)
                } catch (e: Exception) {
                    callback(false, false, "Parse error")
                }
            } else {
                callback(false, false, "Server error")
            }
        }
    }

    /**
     * Get sync statistics
     */
    fun getSyncStats(callback: (lastSync: Long, totalEntries: Int) -> Unit) {
        thread {
            val lastSync = getLastSyncTime("phishtank")
            val totalEntries = database.phishingUrlDao().getAll().size
            callback(lastSync, totalEntries)
        }
    }

    // Helper methods
    private fun extractDomain(url: String): String {
        return url.removePrefix("http://")
            .removePrefix("https://")
            .removePrefix("www.")
            .split("/").first()
    }

    private fun getLastSyncTime(source: String): Long {
        val prefs = context.getSharedPreferences("server_sync", Context.MODE_PRIVATE)
        return prefs.getLong("last_sync_$source", 0)
    }

    private fun saveLastSyncTime(source: String) {
        val prefs = context.getSharedPreferences("server_sync", Context.MODE_PRIVATE)
        prefs.edit().putLong("last_sync_$source", System.currentTimeMillis()).apply()
    }
}

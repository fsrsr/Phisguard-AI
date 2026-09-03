package com.phishguard.ai.core.network

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.phishguard.ai.data.db.PhishingDatabase
import com.phishguard.ai.data.db.PhishingUrl
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.Query
import com.google.firebase.firestore.ListenerRegistration
import com.google.firebase.firestore.ktx.firestore
import com.google.firebase.ktx.Firebase
import kotlin.concurrent.thread

/**
 * ════════════════════════════════════════════════════════════════
 * Firebase Sync Manager — Cloud Phishing Database
 * ════════════════════════════════════════════════════════════════
 *
 * STRUKTUR FIRESTORE:
 *   metadata/versions
 *     ├── phishing_version: "2026.03.13.0001"
 *     └── official_version: "2026.03.13.0001"
 *
 *   phishing_urls/{hash}
 *     ├── url: "bca.100.juta.vercel.app"
 *     ├── reason: "BCA brand mismatch"
 *     ├── reported_count: 42
 *     ├── ai_confirmed: true
 *     └── timestamp: Timestamp
 *
 *   official_urls/{hash}
 *     ├── domain: "bca.co.id"
 *     ├── brand: "BCA"
 *     └── timestamp: Timestamp
 *
 * ALUR VERSION-BASED SYNC:
 * 1. Cek versi lokal vs server (metadata/versions)
 * 2. Jika server lebih baru → fetch only entries setelah lastSyncTime
 * 3. Upsert ke Room DB lokal (bukan download ulang semua!)
 * 4. Update local version string di SharedPreferences
 *
 * COMMUNITY CROWD:
 * - User konfirmasi phishing → uploadPhishingUrl() → Firestore
 * - Semua user lain dapat update versi baru berisi URL ini
 */
class FirebaseSyncManager(private val context: Context) {

    private val TAG = "FirebaseSyncManager"
    private val db: FirebaseFirestore = Firebase.firestore
    private val localDb: PhishingDatabase = PhishingDatabase.getInstance(context)
    private val prefs: SharedPreferences =
        context.getSharedPreferences("phishguard_sync", Context.MODE_PRIVATE)

    companion object {
        // Firestore collection / document paths
        const val COL_PHISHING_URLS  = "phishing_urls"
        const val COL_OFFICIAL_URLS  = "official_urls"
        const val COL_BLOCKED_NUMBERS = "blocked_numbers"
        const val DOC_METADATA       = "metadata/versions"

        // SharedPreferences keys
        const val PREF_LOCAL_PHISHING_VERSION  = "local_phishing_version"
        const val PREF_LOCAL_OFFICIAL_VERSION  = "local_official_version"
        const val PREF_LOCAL_NUMBERS_VERSION   = "local_numbers_version"
        const val PREF_LAST_SYNC_TIME          = "last_sync_time"
        const val PREF_LAST_NUMBER_SYNC_TIME   = "last_number_sync_time"
        const val PREF_LAST_CHECK_TIME         = "last_check_time"

        // Minimum jeda antar check (1 jam = 3.600.000 ms)
        const val CHECK_INTERVAL_MS = 3_600_000L
    }

    // ──────────────────────────────────────────────────────────────
    // PUBLIC: Entry point — dipanggil saat app start
    // ──────────────────────────────────────────────────────────────

    /**
     * Cek versi server vs lokal. Jika berbeda → sync.
     * Berjalan di background thread agar tidak block UI.
     */
    fun checkAndSync(onComplete: (() -> Unit)? = null) {
        val now = System.currentTimeMillis()
        val lastCheck = prefs.getLong(PREF_LAST_CHECK_TIME, 0L)

        // Throttle: jangan check terlalu sering
        if (now - lastCheck < CHECK_INTERVAL_MS) {
            Log.d(TAG, "Sync throttled. Last check: ${(now - lastCheck) / 60000} menit yang lalu.")
            onComplete?.invoke()
            return
        }

        Log.d(TAG, "Memulai version check ke Firebase Firestore...")
        prefs.edit().putLong(PREF_LAST_CHECK_TIME, now).apply()

        db.document(DOC_METADATA).get()
            .addOnSuccessListener { doc ->
                val serverPhishingVersion  = doc.getString("phishing_version")  ?: ""
                val serverOfficialVersion  = doc.getString("official_version")  ?: ""
                val serverNumbersVersion   = doc.getString("numbers_version")   ?: ""
                val localPhishingVersion   = prefs.getString(PREF_LOCAL_PHISHING_VERSION, "") ?: ""
                val localOfficialVersion   = prefs.getString(PREF_LOCAL_OFFICIAL_VERSION, "") ?: ""
                val localNumbersVersion    = prefs.getString(PREF_LOCAL_NUMBERS_VERSION, "") ?: ""

                Log.d(TAG, "Version check:")
                Log.d(TAG, "  Phishing — local='$localPhishingVersion' server='$serverPhishingVersion'")
                Log.d(TAG, "  Official — local='$localOfficialVersion' server='$serverOfficialVersion'")
                Log.d(TAG, "  Numbers  — local='$localNumbersVersion' server='$serverNumbersVersion'")

                var syncsNeeded = 0

                if (serverPhishingVersion != localPhishingVersion && serverPhishingVersion.isNotBlank()) {
                    syncsNeeded++
                    syncPhishingUrls(serverPhishingVersion) {
                        syncsNeeded--
                        if (syncsNeeded == 0) onComplete?.invoke()
                    }
                }

                if (serverOfficialVersion != localOfficialVersion && serverOfficialVersion.isNotBlank()) {
                    syncsNeeded++
                    syncOfficialUrls(serverOfficialVersion) {
                        syncsNeeded--
                        if (syncsNeeded == 0) onComplete?.invoke()
                    }
                }

                if (serverNumbersVersion != localNumbersVersion && serverNumbersVersion.isNotBlank()) {
                    syncsNeeded++
                    syncPhishingNumbers(serverNumbersVersion) {
                        syncsNeeded--
                        if (syncsNeeded == 0) onComplete?.invoke()
                    }
                }

                if (syncsNeeded == 0) {
                    Log.d(TAG, "✅ Database sudah up-to-date.")
                    onComplete?.invoke()
                }
            }
            .addOnFailureListener { e ->
                Log.e(TAG, "Gagal cek versi server: ${e.message}")
                onComplete?.invoke()
            }
    }

    // ──────────────────────────────────────────────────────────────
    // SYNC: Phishing URLs (upsert ke Room DB)
    // ──────────────────────────────────────────────────────────────

    private fun syncPhishingUrls(newVersion: String, onDone: () -> Unit) {
        val lastSyncTime = prefs.getLong(PREF_LAST_SYNC_TIME, 0L)
        Log.d(TAG, "Syncing phishing URLs (since ${lastSyncTime})...")

        // Fetch hanya entries yang baru (incremental — tidak download semua!)
        val query = if (lastSyncTime == 0L) {
            db.collection(COL_PHISHING_URLS).limit(500)
        } else {
            db.collection(COL_PHISHING_URLS)
                .whereGreaterThan("timestamp", com.google.firebase.Timestamp(lastSyncTime / 1000, 0))
                .limit(500)
        }

        query.get()
            .addOnSuccessListener { snapshot ->
                Log.d(TAG, "Phishing URLs diterima: ${snapshot.size()} entries")

                thread {
                    var inserted = 0
                    for (doc in snapshot.documents) {
                        val url    = doc.getString("url")    ?: continue
                        val reason = doc.getString("reason") ?: "Phishing dari database komunitas"
                        val confidence = doc.getDouble("confidence")?.toFloat() ?: 0.9f

                        // UPSERT: Insert jika belum ada, skip jika sudah ada
                        val existing = localDb.phishingUrlDao().findByUrl(url)
                        if (existing == null) {
                            localDb.phishingUrlDao().insert(
                                PhishingUrl(
                                    url = url,
                                    reason = reason,
                                    isCommunityReported = true
                                )
                            )
                            inserted++
                        }
                    }
                    Log.d(TAG, "✅ Upsert phishing URLs: $inserted baru dimasukkan.")

                    // Simpan versi baru ke lokal
                    prefs.edit()
                        .putString(PREF_LOCAL_PHISHING_VERSION, newVersion)
                        .putLong(PREF_LAST_SYNC_TIME, System.currentTimeMillis())
                        .apply()

                    onDone()
                }
            }
            .addOnFailureListener { e ->
                Log.e(TAG, "Gagal sync phishing URLs: ${e.message}")
                onDone()
            }
    }

    // ──────────────────────────────────────────────────────────────
    // SYNC: Official URLs (whitelist resmi)
    // ──────────────────────────────────────────────────────────────

    private fun syncOfficialUrls(newVersion: String, onDone: () -> Unit) {
        Log.d(TAG, "Syncing official URLs...")
        db.collection(COL_OFFICIAL_URLS).limit(2000).get()
            .addOnSuccessListener { snapshot ->
                Log.d(TAG, "Official URLs diterima: ${snapshot.size()} entries")
                thread {
                    var inserted = 0
                    for (doc in snapshot.documents) {
                        val domain = doc.getString("domain") ?: continue
                        val organization  = doc.getString("brand")  ?: "Verified Domain"
                        val category = doc.getString("category") ?: "unknown"
                        val existing = localDb.officialUrlDao().findByDomain(domain)
                        if (existing == null) {
                            localDb.officialUrlDao().insert(
                                com.phishguard.ai.data.db.OfficialUrl(
                                    domain = domain,
                                    organization = organization,
                                    category = category
                                )
                            )
                            inserted++
                        }
                    }
                    Log.d(TAG, "✅ Upsert official URLs: $inserted baru dimasukkan.")
                    prefs.edit().putString(PREF_LOCAL_OFFICIAL_VERSION, newVersion).apply()
                    onDone()
                }
            }
            .addOnFailureListener { e ->
                Log.e(TAG, "Gagal sync official URLs: ${e.message}")
                onDone()
            }
    }

    // ──────────────────────────────────────────────────────────────
    // SYNC: Blocked Numbers (nomor penipu dari komunitas)
    // ──────────────────────────────────────────────────────────────

    private fun syncPhishingNumbers(newVersion: String, onDone: () -> Unit) {
        val lastSyncTime = prefs.getLong(PREF_LAST_NUMBER_SYNC_TIME, 0L)
        Log.d(TAG, "Syncing blocked numbers (since ${lastSyncTime})...")

        val query = if (lastSyncTime == 0L) {
            db.collection(COL_BLOCKED_NUMBERS).limit(500)
        } else {
            db.collection(COL_BLOCKED_NUMBERS)
                .whereGreaterThan("timestamp", com.google.firebase.Timestamp(lastSyncTime / 1000, 0))
                .limit(500)
        }

        query.get()
            .addOnSuccessListener { snapshot ->
                Log.d(TAG, "Blocked numbers diterima: ${snapshot.size()} entries")
                thread {
                    var inserted = 0
                    for (doc in snapshot.documents) {
                        val number = doc.getString("number") ?: continue
                        val reason = doc.getString("reason") ?: "Nomor dari database komunitas"
                        val confidence = doc.getDouble("confidence")?.toFloat() ?: 0.9f

                        // UPSERT: lewati nomor yang sudah ada agar tidak menimpa
                        // entri "user_report" milik pengguna sendiri.
                        val existing = localDb.phishingNumberDao().findByNumber(number)
                        if (existing == null) {
                            localDb.phishingNumberDao().insert(
                                com.phishguard.ai.data.db.PhishingNumber(
                                    number = number,
                                    reason = reason,
                                    source = "community",
                                    confidence = confidence
                                )
                            )
                            inserted++
                        }
                    }
                    Log.d(TAG, "✅ Upsert blocked numbers: $inserted baru dimasukkan.")
                    prefs.edit()
                        .putString(PREF_LOCAL_NUMBERS_VERSION, newVersion)
                        .putLong(PREF_LAST_NUMBER_SYNC_TIME, System.currentTimeMillis())
                        .apply()
                    onDone()
                }
            }
            .addOnFailureListener { e ->
                Log.e(TAG, "Gagal sync blocked numbers: ${e.message}")
                onDone()
            }
    }

    // ──────────────────────────────────────────────────────────────
    // COMMUNITY UPLOAD: User konfirmasi phishing → upload ke server
    // ──────────────────────────────────────────────────────────────

    /**
     * Dipanggil saat user menekan "BLOKIR" di HITL overlay.
     * URL phishing dikirim ke Firestore → membantu jutaan user lain.
     */
    fun uploadPhishingUrl(
        url: String,
        reason: String,
        confidence: Float,
        onSuccess: (() -> Unit)? = null,
        onFailure: ((String) -> Unit)? = null
    ) {
        val urlHash = url.replace(Regex("[^a-zA-Z0-9]"), "_").take(100)

        Log.d(TAG, "📤 Uploading phishing URL ke komunitas: $url")

        val data = hashMapOf(
            "url"             to url,
            "reason"          to reason,
            "confidence"      to confidence,
            "reported_count"  to 1,
            "ai_confirmed"    to (confidence >= 0.80f),
            "timestamp"       to com.google.firebase.Timestamp.now(),
            "source"          to "user_report"
        )

        db.collection(COL_PHISHING_URLS)
            .document(urlHash)
            .set(data, com.google.firebase.firestore.SetOptions.merge())
            .addOnSuccessListener {
                Log.d(TAG, "✅ URL berhasil diupload ke komunitas: $url")
                // Increment reported_count di server
                db.collection(COL_PHISHING_URLS).document(urlHash)
                    .update("reported_count", com.google.firebase.firestore.FieldValue.increment(1))
                // Bump versi di metadata agar user lain sync
                bumpServerVersion("phishing")
                onSuccess?.invoke()
            }
            .addOnFailureListener { e ->
                Log.e(TAG, "Gagal upload URL phishing: ${e.message}")
                onFailure?.invoke(e.message ?: "Unknown error")
            }
    }

    /**
     * Dipanggil saat pengguna menekan "Blokir Nomor" di overlay SMS.
     * Nomor penipu dikirim ke komunitas → melindungi penerima berikutnya:
     * pada sync berikutnya nomor masuk ke DB lokal mereka, dan Layer 2
     * (AnalysisPipeline) langsung memunculkan peringatan sebelum korban
     * sempat menanggapi.
     */
    fun uploadPhishingNumber(
        number: String,
        reason: String,
        confidence: Float,
        onSuccess: (() -> Unit)? = null,
        onFailure: ((String) -> Unit)? = null
    ) {
        val clean = number.trim()
        if (clean.length < 5) {                 // shortcode/alfanumerik pengirim resmi
            onFailure?.invoke("Nomor terlalu pendek untuk dibagikan"); return
        }
        val numberHash = clean.replace(Regex("[^a-zA-Z0-9+]"), "_").take(100)

        Log.d(TAG, "📤 Uploading nomor penipu ke komunitas: $clean")

        val data = hashMapOf(
            "number"          to clean,
            "reason"          to reason,
            "confidence"      to confidence,
            "reported_count"  to 1,
            "ai_confirmed"    to (confidence >= 0.80f),
            "timestamp"       to com.google.firebase.Timestamp.now(),
            "source"          to "user_report"
        )

        db.collection(COL_BLOCKED_NUMBERS)
            .document(numberHash)
            .set(data, com.google.firebase.firestore.SetOptions.merge())
            .addOnSuccessListener {
                Log.d(TAG, "✅ Nomor berhasil diupload ke komunitas: $clean")
                db.collection(COL_BLOCKED_NUMBERS).document(numberHash)
                    .update("reported_count", com.google.firebase.firestore.FieldValue.increment(1))
                bumpServerVersion("numbers")
                onSuccess?.invoke()
            }
            .addOnFailureListener { e ->
                Log.e(TAG, "Gagal upload nomor penipu: ${e.message}")
                onFailure?.invoke(e.message ?: "Unknown error")
            }
    }

    /**
     * Simpan laporan anonim untuk pipeline dedup/verdict.
     * Isi pesan mentah tidak pernah dikirim.
     */
    fun uploadUserReport(
        message: String,
        urls: List<String>,
        source: String,
        reason: String,
        confidence: Float,
        reportId: String = java.util.UUID.randomUUID().toString(),
        onSuccess: ((String) -> Unit)? = null,
        onFailure: ((String) -> Unit)? = null
    ) {
        val messageHash = sha256(message)
        val data = hashMapOf(
            "message_hash" to messageHash,
            "urls" to urls.distinct().take(10),
            "source" to source,
            "reason" to reason.take(500),
            "confidence" to confidence.coerceIn(0f, 1f),
            "status" to "pending",
            "created_at" to com.google.firebase.Timestamp.now()
        )

        db.collection("reports").document(reportId).set(data)
            .addOnSuccessListener {
                Log.d(TAG, "✅ Laporan anonim tersimpan: ${messageHash.take(12)}")
                onSuccess?.invoke(reportId)
            }
            .addOnFailureListener { e ->
                Log.e(TAG, "Gagal menyimpan laporan: ${e.message}")
                onFailure?.invoke(e.message ?: "Unknown error")
            }
    }

    fun listenToReports(
        reportRecords: Set<String>,
        onChanged: (reportId: String, status: String, feedback: String) -> Unit
    ): List<ListenerRegistration> {
        val listeners = mutableListOf<ListenerRegistration>()
        val records = reportRecords.mapNotNull { record ->
            val parts = record.split("|", limit = 4)
            if (parts.size >= 3) parts[0] to parts[2] else null
        }
        records.forEach { (localId, indicator) ->
            if (localId.isBlank()) return@forEach
            listeners += db.collection("reports").document(localId)
                .addSnapshotListener { snapshot, error ->
                    if (error != null || snapshot == null || !snapshot.exists()) return@addSnapshotListener
                    emitReportStatus(localId, snapshot, onChanged)
                }
            // Backward compatibility: reports created before localId == Firestore ID.
            if (indicator.isNotBlank()) {
                listeners += db.collection("reports")
                    .whereArrayContains("urls", indicator)
                    .addSnapshotListener { snapshot, error ->
                        if (error != null || snapshot == null) return@addSnapshotListener
                        snapshot.documents.forEach { emitReportStatus(localId, it, onChanged) }
                    }
            }
        }
        return listeners
    }

    private fun emitReportStatus(
        localId: String,
        snapshot: com.google.firebase.firestore.DocumentSnapshot,
        onChanged: (String, String, String) -> Unit
    ) {
        val rawStatus = snapshot.getString("status").orEmpty().lowercase()
        val status = when (rawStatus) {
            "done", "selesai", "completed" -> "Selesai"
            "rejected", "ditolak" -> "Ditolak"
            "processing", "diproses" -> "Diproses"
            else -> "Terkirim"
        }
        onChanged(localId, status, snapshot.getString("feedback").orEmpty())
    }

    private fun sha256(value: String): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(value.trim().lowercase().toByteArray())
            .joinToString("") { "%02x".format(it) }

    /**
     * Perbarui versi database di server agar semua user lain trigger sync.
     * Format versi: "YYYY.MM.DD.XXXX" — sederhana dan mudah dibandingkan.
     */
    private fun bumpServerVersion(type: String) {
        val newVersion = generateVersion()
        val field = "${type}_version"
        val data = hashMapOf(
            field to newVersion,
            "last_updated" to com.google.firebase.Timestamp.now()
        )
        db.document(DOC_METADATA)
            .set(data, com.google.firebase.firestore.SetOptions.merge())
            .addOnSuccessListener { Log.d(TAG, "Version bumped: $field=$newVersion") }
            .addOnFailureListener { e -> Log.e(TAG, "Gagal bump version: ${e.message}") }
    }

    private fun generateVersion(): String {
        val sdf = java.text.SimpleDateFormat("yyyy.MM.dd", java.util.Locale.getDefault())
        val dateStr = sdf.format(java.util.Date())
        val seq = (System.currentTimeMillis() % 10000).toString().padStart(4, '0')
        return "$dateStr.$seq"
    }

    // ──────────────────────────────────────────────────────────────
    // BULK UPLOAD SEEDER: Dipanggil manual jika ingin upload 1000+ CSV
    // ──────────────────────────────────────────────────────────────
    fun bulkUploadOfficialUrlsFromAssets() {
        Log.d(TAG, "Mulai baca official_data.txt dari assets...")
        thread {
            try {
                val inputStream = context.assets.open("official_data.txt")
                val lines = inputStream.bufferedReader().readLines()
                    .map { it.trim() }
                    .filter { it.isNotBlank() }

                Log.d(TAG, "Terdapat ${lines.size} URL untuk di-upload.")
                if (lines.isEmpty()) return@thread

                // Firestore maksimal 500 document per sekali writeBatch()
                val chunks = lines.chunked(450)
                
                var totalSuccess = 0
                for ((index, chunk) in chunks.withIndex()) {
                    val batch = db.batch()
                    for (rawUrl in chunk) {
                        // Hilangkan http://, https://, dan www. agar murni domain
                        var domain = rawUrl.lowercase()
                            .removePrefix("http://")
                            .removePrefix("https://")
                            .removePrefix("www.")
                        if (domain.endsWith("/")) domain = domain.dropLast(1)
                        if (domain.contains("/")) domain = domainSubstring(domain)

                        val hash = domain.replace(Regex("[^a-zA-Z0-9]"), "_").take(100)
                        
                        // Menentukan organization secara otomatis karena format default
                        val org = if (domain.contains("bank")) "Sektor Perbankan" 
                                  else if (domain.endsWith("go.id")) "Sektor Pemerintahan"
                                  else "Official Domain"

                        val docRef = db.collection(COL_OFFICIAL_URLS).document(hash)
                        val data = hashMapOf(
                            "domain" to domain,
                            "brand" to org,
                            "category" to "system_seed",
                            "timestamp" to com.google.firebase.Timestamp.now()
                        )
                        batch.set(docRef, data, com.google.firebase.firestore.SetOptions.merge())
                    }

                    batch.commit()
                        .addOnSuccessListener {
                            totalSuccess += chunk.size
                            Log.d(TAG, "✅ Batch ${index + 1}/${chunks.size} sukses terkirim!")
                            if (index == chunks.size - 1) {
                                bumpServerVersion("official") // Minta semua user lain sync
                                Log.d(TAG, "🎉 SEMUA URL SELESAI DI-UPLOAD. TOTAL = $totalSuccess")
                            }
                        }
                        .addOnFailureListener { e ->
                            Log.e(TAG, "❌ Batch ${index + 1} gagal", e)
                        }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Gagal bulk upload: ${e.message}")
            }
        }
    }

    private fun domainSubstring(domain: String): String {
        val slashIndex = domain.indexOf('/')
        return if (slashIndex != -1) domain.substring(0, slashIndex) else domain
    }
}

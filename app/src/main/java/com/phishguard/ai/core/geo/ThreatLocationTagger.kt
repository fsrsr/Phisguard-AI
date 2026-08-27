package com.phishguard.ai.core.geo

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.util.Log
import androidx.core.content.ContextCompat
import com.phishguard.ai.data.AppPreferences
import com.phishguard.ai.data.db.PhishingDatabase
import com.phishguard.ai.data.db.ThreatLocation
import kotlin.concurrent.thread

/**
 * Menandai ancaman terkonfirmasi dengan perkiraan lokasi, untuk peta pola.
 *
 * Tiga batasan yang disengaja, karena ini aplikasi keamanan yang justru
 * ada untuk melindungi data pengguna:
 *
 * 1. **Opt-in.** Tidak melakukan apa pun kecuali pengguna menyalakan
 *    sendiri lewat Pengaturan. Bawaannya mati.
 * 2. **Lokasi kasar, tidak pernah presisi.** Meminta izin COARSE saja, dan
 *    koordinatnya dibulatkan lagi ke ~1 km sebelum disimpan.
 * 3. **Tidak melacak.** Hanya membaca lokasi TERAKHIR yang sudah diketahui
 *    sistem — tidak menyalakan GPS, tidak berlangganan pembaruan, tidak
 *    menguras baterai. Kalau sistem belum punya lokasi, ancaman itu
 *    dicatat tanpa koordinat, bukan memaksa mencari.
 *
 * Konsekuensinya lokasinya bisa basi beberapa menit. Untuk memetakan titik
 * rawan tingkat kelurahan itu tidak masalah, dan pertukarannya sepadan.
 */
object ThreatLocationTagger {

    private const val TAG = "ThreatLocationTagger"

    /** Lokasi lebih tua dari ini diabaikan — terlalu basi untuk bermakna. */
    private const val MAX_AGE_MS = 30 * 60 * 1000L

    fun isEnabled(context: Context): Boolean =
        AppPreferences(context).threatMapEnabled && hasPermission(context)

    fun hasPermission(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED

    /**
     * Catat satu ancaman terkonfirmasi. Aman dipanggil kapan saja: bila
     * fiturnya mati atau izinnya tidak ada, fungsi ini tidak melakukan
     * apa-apa.
     */
    fun record(
        context: Context,
        crimeType: String,
        severity: Float,
        source: String,
        label: String
    ) {
        if (!isEnabled(context)) return
        thread {
            try {
                val loc = lastKnownCoarseLocation(context)
                if (loc == null) {
                    Log.d(TAG, "Belum ada lokasi diketahui — ancaman tidak dipetakan.")
                    return@thread
                }
                PhishingDatabase.getInstance(context.applicationContext)
                    .threatLocationDao()
                    .insert(
                        ThreatLocation(
                            latitude = ThreatLocation.roundForPrivacy(loc.first),
                            longitude = ThreatLocation.roundForPrivacy(loc.second),
                            crimeType = crimeType,
                            severity = severity.coerceIn(0f, 1f),
                            source = source,
                            label = label.take(80)
                        )
                    )
                Log.d(TAG, "Ancaman dipetakan: $crimeType dari $source")
            } catch (e: Exception) {
                Log.e(TAG, "Gagal mencatat lokasi ancaman", e)
            }
        }
    }

    /** @return pasangan lat/lon, atau null bila tidak ada yang cukup segar. */
    private fun lastKnownCoarseLocation(context: Context): Pair<Double, Double>? {
        if (!hasPermission(context)) return null
        return try {
            val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
                ?: return null
            // NETWORK dulu: lebih kasar, lebih hemat, dan itu memang yang
            // kita inginkan. GPS hanya dipakai bila sistem kebetulan sudah
            // punya fix — kita tidak pernah memintanya menyala.
            val providers = listOf(LocationManager.NETWORK_PROVIDER, LocationManager.PASSIVE_PROVIDER)
            val now = System.currentTimeMillis()
            providers.asSequence()
                .mapNotNull { p ->
                    @Suppress("MissingPermission")
                    try { lm.getLastKnownLocation(p) } catch (e: SecurityException) { null }
                }
                .filter { now - it.time <= MAX_AGE_MS }
                .maxByOrNull { it.time }
                ?.let { it.latitude to it.longitude }
        } catch (e: Exception) {
            Log.e(TAG, "lastKnownCoarseLocation error", e)
            null
        }
    }
}

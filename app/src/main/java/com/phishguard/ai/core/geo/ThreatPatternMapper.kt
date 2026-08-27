package com.phishguard.ai.core.geo

import com.phishguard.ai.data.db.ThreatLocation
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * Mengubah ancaman terekam jadi tiga dimensi pola: spasial, temporal, dan
 * kategorikal — sesuai spesifikasi "Pemetaan Pola Kejahatan".
 *
 * Murni Kotlin tanpa dependensi Android (kecuali org.json yang tersedia di
 * runtime Android dan di JVM lewat json-unit), jadi bisa diuji langsung.
 */
object ThreatPatternMapper {

    /** Kategori yang dipetakan, beserta label yang dibaca pengguna. */
    enum class Category(val id: String, val label: String) {
        PHISHING("PHISHING", "Situs phishing"),
        JUDOL("JUDOL", "Judi online"),
        SCAM_MESSAGE("SCAM_MESSAGE", "Pesan penipuan"),
        FRAUD_CALL("FRAUD_CALL", "Panggilan penipuan"),
        LAINNYA("LAINNYA", "Lainnya");

        companion object {
            fun from(id: String): Category =
                entries.firstOrNull { it.id.equals(id, ignoreCase = true) } ?: LAINNYA
        }
    }

    /** Rentang waktu untuk pola temporal (bagian B spesifikasi). */
    enum class TimeBand(val label: String, val startHour: Int, val endHour: Int) {
        DINI_HARI("Dini hari (00–06)", 0, 6),
        PAGI("Pagi (06–12)", 6, 12),
        SIANG("Siang (12–18)", 12, 18),
        MALAM("Malam (18–24)", 18, 24);

        companion object {
            fun of(hour: Int): TimeBand =
                entries.first { hour >= it.startHour && hour < it.endHour }
        }
    }

    // ── Bagian 4 spesifikasi: skema payload GeoJSON ─────────────────────

    /**
     * Bangun FeatureCollection GeoJSON.
     *
     * PERHATIAN: GeoJSON menuliskan koordinat sebagai **[longitude,
     * latitude]** — kebalikan dari urutan "lat, lon" yang biasa diucapkan.
     * Menukarnya adalah kekeliruan paling umum pada data spasial, dan
     * gejalanya halus: titik-titik muncul di tempat yang masuk akal tapi
     * salah. Diuji di ThreatPatternMapperTest.
     */
    fun toGeoJson(locations: List<ThreatLocation>): JSONObject {
        val features = JSONArray()
        for (l in locations) {
            val geometry = JSONObject()
                .put("type", "Point")
                .put("coordinates", JSONArray().put(l.longitude).put(l.latitude))

            val properties = JSONObject()
                .put("id", "PG-${l.id}")
                .put("type", Category.from(l.crimeType).label)
                .put("time_of_occurrence", iso8601(l.timestamp))
                .put("risk_weight", l.severity)
                .put("source", l.source)
                .put("label", l.label)

            features.put(
                JSONObject()
                    .put("type", "Feature")
                    .put("geometry", geometry)
                    .put("properties", properties)
            )
        }
        return JSONObject()
            .put("type", "FeatureCollection")
            .put("features", features)
    }

    // ── Bagian A: titik rawan spasial ───────────────────────────────────

    data class Hotspot(
        val latitude: Double,
        val longitude: Double,
        val count: Int,
        /** 0..1 — dipakai memilih gradasi warna pada peta. */
        val intensity: Float
    )

    /**
     * Kelompokkan ancaman ke sel grid, hitung intensitasnya.
     *
     * Sengaja memakai grid, bukan K-Means atau DBSCAN seperti disebut di
     * spesifikasi. Alasannya: koordinat sudah dibulatkan ke ~1 km demi
     * privasi, jadi presisi hasil clustering canggih akan hilang percuma —
     * dan grid berjalan seketika di ponsel tanpa pustaka tambahan.
     *
     * ponytail: grid tetap, ganti ke DBSCAN bila nanti presisinya dinaikkan.
     */
    fun hotspots(locations: List<ThreatLocation>, gridDegrees: Double = 0.01): List<Hotspot> {
        if (locations.isEmpty()) return emptyList()
        val buckets = locations.groupBy {
            snap(it.latitude, gridDegrees) to snap(it.longitude, gridDegrees)
        }
        val max = buckets.values.maxOf { it.size }.toFloat()
        return buckets.map { (key, items) ->
            Hotspot(
                latitude = key.first,
                longitude = key.second,
                count = items.size,
                intensity = items.size / max
            )
        }.sortedByDescending { it.count }
    }

    // ── Bagian B: pola temporal ─────────────────────────────────────────

    /** Berapa ancaman per rentang waktu. Rentang kosong tetap disertakan. */
    fun byTimeBand(locations: List<ThreatLocation>): Map<TimeBand, Int> {
        val counts = TimeBand.entries.associateWith { 0 }.toMutableMap()
        for (l in locations) {
            val band = TimeBand.of(hourOf(l.timestamp))
            counts[band] = (counts[band] ?: 0) + 1
        }
        return counts
    }

    /** Sebaran per jam 0..23, untuk grafik garis. */
    fun byHour(locations: List<ThreatLocation>): IntArray {
        val hours = IntArray(24)
        for (l in locations) hours[hourOf(l.timestamp)]++
        return hours
    }

    // ── Bagian C: tipologi ──────────────────────────────────────────────

    fun byCategory(locations: List<ThreatLocation>): Map<Category, Int> =
        locations.groupingBy { Category.from(it.crimeType) }.eachCount()

    // ── Helper ──────────────────────────────────────────────────────────

    private fun snap(value: Double, grid: Double): Double =
        Math.round(value / grid) * grid

    private fun hourOf(epochMs: Long): Int {
        val cal = java.util.Calendar.getInstance()
        cal.timeInMillis = epochMs
        return cal.get(java.util.Calendar.HOUR_OF_DAY)
    }

    private fun iso8601(epochMs: Long): String {
        val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US)
        fmt.timeZone = TimeZone.getTimeZone("UTC")
        return fmt.format(Date(epochMs))
    }
}

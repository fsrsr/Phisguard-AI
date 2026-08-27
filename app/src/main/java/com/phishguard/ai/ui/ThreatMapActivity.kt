package com.phishguard.ai.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Color
import android.os.Bundle
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.phishguard.ai.R
import com.phishguard.ai.core.geo.ThreatPatternMapper
import com.phishguard.ai.core.geo.ThreatPatternMapper.Category
import com.phishguard.ai.core.geo.ThreatPatternMapper.TimeBand
import com.phishguard.ai.data.db.PhishingDatabase
import com.phishguard.ai.data.db.ThreatLocation
import org.osmdroid.config.Configuration
import org.osmdroid.tileprovider.tilesource.TileSourceFactory
import org.osmdroid.util.GeoPoint
import org.osmdroid.views.MapView
import org.osmdroid.views.overlay.Overlay
import kotlin.concurrent.thread
import kotlin.math.max

/**
 * Peta pola ancaman — tiga dimensi dari spesifikasi pemetaan:
 * spasial (titik rawan), temporal (filter rentang waktu), kategorikal
 * (filter jenis ancaman).
 *
 * Titik rawan digambar sebagai lingkaran berskala intensitas, bukan
 * heatmap piksel: dengan koordinat yang sudah dibulatkan ~1 km demi
 * privasi, gradasi halus hanya akan mengarang presisi yang tidak ada.
 */
class ThreatMapActivity : AppCompatActivity() {

    private lateinit var map: MapView
    private lateinit var tvSummary: TextView
    private lateinit var tvEmpty: TextView

    private var semua: List<ThreatLocation> = emptyList()
    private var bandTerpilih: TimeBand? = null
    private val kategoriTersembunyi = mutableSetOf<Category>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // osmdroid butuh user-agent; tanpa ini server tile menolak permintaan.
        Configuration.getInstance().userAgentValue = packageName
        setContentView(R.layout.activity_threat_map)

        map = findViewById(R.id.mapView)
        tvSummary = findViewById(R.id.tvMapSummary)
        tvEmpty = findViewById(R.id.tvMapEmpty)
        map.setTileSource(TileSourceFactory.MAPNIK)
        map.setMultiTouchControls(true)
        map.controller.setZoom(11.0)

        bangunFilterWaktu(findViewById(R.id.chipTime))
        bangunFilterKategori(findViewById(R.id.chipCategory))

        findViewById<MaterialButton>(R.id.btnExportGeoJson).setOnClickListener { eksporGeoJson() }

        muatData()
    }

    override fun onResume() { super.onResume(); map.onResume() }
    override fun onPause() { super.onPause(); map.onPause() }

    private fun muatData() {
        thread {
            val data = try {
                PhishingDatabase.getInstance(applicationContext).threatLocationDao().getAll()
            } catch (e: Exception) {
                emptyList()
            }
            runOnUiThread { semua = data; gambar() }
        }
    }

    // ── Filter ──────────────────────────────────────────────────────────

    private fun bangunFilterWaktu(grup: ChipGroup) {
        fun chip(teks: String, band: TimeBand?): Chip = Chip(this).apply {
            text = teks
            isCheckable = true
            isChecked = band == null
            setOnClickListener { bandTerpilih = band; gambar() }
        }
        grup.addView(chip(getString(R.string.map_all_time), null))
        TimeBand.entries.forEach { grup.addView(chip(it.label, it)) }
    }

    private fun bangunFilterKategori(grup: ChipGroup) {
        Category.entries.forEach { kategori ->
            grup.addView(Chip(this).apply {
                text = kategori.label
                isCheckable = true
                isChecked = true
                chipBackgroundColor = android.content.res.ColorStateList
                    .valueOf(warnaKategori(kategori) and 0x33FFFFFF)
                setOnCheckedChangeListener { _, dicentang ->
                    if (dicentang) kategoriTersembunyi.remove(kategori)
                    else kategoriTersembunyi.add(kategori)
                    gambar()
                }
            })
        }
    }

    private fun tersaring(): List<ThreatLocation> = semua.filter { l ->
        val kategoriLolos = Category.from(l.crimeType) !in kategoriTersembunyi
        val waktuLolos = bandTerpilih?.let { band ->
            val c = java.util.Calendar.getInstance().apply { timeInMillis = l.timestamp }
            TimeBand.of(c.get(java.util.Calendar.HOUR_OF_DAY)) == band
        } ?: true
        kategoriLolos && waktuLolos
    }

    // ── Menggambar ──────────────────────────────────────────────────────

    private fun gambar() {
        val data = tersaring()
        map.overlays.clear()

        val titikRawan = ThreatPatternMapper.hotspots(data)
        tvSummary.text = getString(R.string.map_summary, data.size, titikRawan.size)
        tvEmpty.visibility = if (data.isEmpty()) android.view.View.VISIBLE else android.view.View.GONE

        if (data.isEmpty()) { map.invalidate(); return }

        titikRawan.forEach { h ->
            map.overlays.add(LingkaranRawan(GeoPoint(h.latitude, h.longitude), h.intensity, h.count))
        }
        // Fokuskan peta ke titik paling padat.
        titikRawan.firstOrNull()?.let {
            map.controller.setCenter(GeoPoint(it.latitude, it.longitude))
        }
        map.invalidate()
    }

    /** Lingkaran sederhana; radius & warna mengikuti intensitas. */
    private inner class LingkaranRawan(
        private val titik: GeoPoint,
        private val intensitas: Float,
        private val jumlah: Int
    ) : Overlay() {
        override fun draw(c: android.graphics.Canvas, osm: MapView?, shadow: Boolean) {
            if (shadow || osm == null) return
            val p = android.graphics.Point()
            osm.projection.toPixels(titik, p)
            val radius = 18f + intensitas * 42f
            val cat = android.graphics.Paint().apply {
                isAntiAlias = true
                color = gradasi(intensitas)
                alpha = 110
            }
            c.drawCircle(p.x.toFloat(), p.y.toFloat(), radius, cat)
            cat.alpha = 235
            cat.style = android.graphics.Paint.Style.STROKE
            cat.strokeWidth = 3f
            c.drawCircle(p.x.toFloat(), p.y.toFloat(), radius, cat)
            c.drawText(
                jumlah.toString(),
                p.x.toFloat() - 6f, p.y.toFloat() + 6f,
                android.graphics.Paint().apply {
                    isAntiAlias = true; color = Color.WHITE
                    textSize = 26f; isFakeBoldText = true
                }
            )
        }
    }

    /** Hijau (jarang) → merah (padat), sesuai spesifikasi bagian A. */
    private fun gradasi(intensitas: Float): Int {
        val t = intensitas.coerceIn(0f, 1f)
        val merah = (0x10 + t * (0xEF - 0x10)).toInt()
        val hijau = (0xB9 - t * (0xB9 - 0x44)).toInt()
        return Color.rgb(merah, max(hijau, 0x44), 0x50)
    }

    private fun warnaKategori(c: Category): Int = when (c) {
        Category.PHISHING -> Color.rgb(0xEF, 0x44, 0x44)
        Category.JUDOL -> Color.rgb(0xF5, 0x9E, 0x0B)
        Category.SCAM_MESSAGE -> Color.rgb(0x43, 0x61, 0xEE)
        Category.FRAUD_CALL -> Color.rgb(0x10, 0xB9, 0x81)
        Category.LAINNYA -> Color.rgb(0x94, 0xA3, 0xB8)
    }

    // ── Ekspor ──────────────────────────────────────────────────────────

    private fun eksporGeoJson() {
        val data = tersaring()
        val json = ThreatPatternMapper.toGeoJson(data).toString(2)
        (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
            .setPrimaryClip(ClipData.newPlainText("PhishGuard GeoJSON", json))
        Toast.makeText(this, getString(R.string.map_exported, data.size), Toast.LENGTH_LONG).show()
    }
}

package com.phishguard.ai.core.geo

import com.phishguard.ai.data.db.ThreatLocation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Calendar

/** Mengunci tiga dimensi pola dan bentuk payload GeoJSON. */
class ThreatPatternMapperTest {

    private fun waktu(jam: Int): Long {
        val c = Calendar.getInstance()
        c.set(2026, Calendar.AUGUST, 25, jam, 30, 0)
        c.set(Calendar.MILLISECOND, 0)
        return c.timeInMillis
    }

    private fun titik(
        lat: Double = -6.9175, lon: Double = 107.6191,
        jam: Int = 23, tipe: String = "PHISHING", severity: Float = 0.8f
    ) = ThreatLocation(
        id = 1, latitude = lat, longitude = lon, timestamp = waktu(jam),
        crimeType = tipe, severity = severity, source = "Chrome", label = "contoh.tk"
    )

    @Test
    fun `koordinat GeoJSON ditulis longitude dulu baru latitude`() {
        // Kekeliruan spasial paling umum. Titiknya tetap tampak masuk akal
        // kalau tertukar, jadi hanya test yang bisa menahannya.
        val k = ThreatPatternMapper.toGeoJson(listOf(titik()))
            .getJSONArray("features").getJSONObject(0)
            .getJSONObject("geometry").getJSONArray("coordinates")
        assertEquals(107.6191, k.getDouble(0), 0.0001)  // longitude dulu
        assertEquals(-6.9175, k.getDouble(1), 0.0001)   // baru latitude
    }

    @Test
    fun `bentuk payload sesuai spesifikasi`() {
        val json = ThreatPatternMapper.toGeoJson(listOf(titik()))
        assertEquals("FeatureCollection", json.getString("type"))
        val f = json.getJSONArray("features").getJSONObject(0)
        assertEquals("Feature", f.getString("type"))
        assertEquals("Point", f.getJSONObject("geometry").getString("type"))
        val p = f.getJSONObject("properties")
        listOf("id", "type", "time_of_occurrence", "risk_weight").forEach {
            assertTrue("field '$it' hilang", p.has(it))
        }
        assertEquals(0.8, p.getDouble("risk_weight"), 0.001)
    }

    @Test
    fun `waktu ditulis dalam UTC berformat ISO-8601`() {
        val w = ThreatPatternMapper.toGeoJson(listOf(titik()))
            .getJSONArray("features").getJSONObject(0)
            .getJSONObject("properties").getString("time_of_occurrence")
        assertTrue("format salah: $w", Regex("""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z""").matches(w))
    }

    @Test
    fun `titik berdekatan menyatu jadi satu hotspot`() {
        val data = listOf(
            titik(lat = -6.9175, lon = 107.6191),
            titik(lat = -6.9178, lon = 107.6193),
            titik(lat = -6.2000, lon = 106.8000)
        )
        val h = ThreatPatternMapper.hotspots(data)
        assertEquals(2, h.size)
        assertEquals(2, h.first().count)
        assertEquals(1.0f, h.first().intensity, 0.001f)
    }

    @Test
    fun `pola temporal mengelompokkan per rentang waktu`() {
        val b = ThreatPatternMapper.byTimeBand(
            listOf(titik(jam = 23), titik(jam = 2), titik(jam = 3), titik(jam = 9))
        )
        assertEquals(2, b[ThreatPatternMapper.TimeBand.DINI_HARI])
        assertEquals(1, b[ThreatPatternMapper.TimeBand.PAGI])
        assertEquals(1, b[ThreatPatternMapper.TimeBand.MALAM])
        assertEquals(0, b[ThreatPatternMapper.TimeBand.SIANG])
    }

    @Test
    fun `sebaran per jam menempatkan kejadian di jamnya`() {
        val h = ThreatPatternMapper.byHour(listOf(titik(jam = 23), titik(jam = 23), titik(jam = 5)))
        assertEquals(2, h[23]); assertEquals(1, h[5]); assertEquals(0, h[12])
    }

    @Test
    fun `tipologi menghitung per kategori dan tipe asing jadi Lainnya`() {
        val c = ThreatPatternMapper.byCategory(listOf(
            titik(tipe = "PHISHING"), titik(tipe = "PHISHING"),
            titik(tipe = "JUDOL"), titik(tipe = "TIDAK_DIKENAL")
        ))
        assertEquals(2, c[ThreatPatternMapper.Category.PHISHING])
        assertEquals(1, c[ThreatPatternMapper.Category.JUDOL])
        assertEquals(1, c[ThreatPatternMapper.Category.LAINNYA])
    }

    @Test
    fun `koordinat dibulatkan demi privasi`() {
        assertEquals(-6.92, ThreatLocation.roundForPrivacy(-6.917534), 0.0001)
        assertEquals(107.62, ThreatLocation.roundForPrivacy(107.619112), 0.0001)
    }

    @Test
    fun `daftar kosong tidak membuat crash`() {
        assertEquals(0, ThreatPatternMapper.toGeoJson(emptyList()).getJSONArray("features").length())
        assertTrue(ThreatPatternMapper.hotspots(emptyList()).isEmpty())
        assertEquals(24, ThreatPatternMapper.byHour(emptyList()).size)
    }
}

package com.phishguard.ai.data.db

import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query

/**
 * Satu ancaman yang tercatat beserta perkiraan lokasinya.
 *
 * PRIVASI — baca sebelum mengubah apa pun di sini:
 *
 * Tabel ini hanya terisi bila pengguna MENYALAKANNYA sendiri (bawaannya
 * mati), dan hanya saat ancaman benar-benar dikonfirmasi — bukan setiap
 * kali sebuah URL dipindai. Koordinatnya sengaja dibulatkan ke ~1 km lewat
 * [roundForPrivacy]: cukup untuk melihat titik rawan tingkat kelurahan,
 * tidak cukup untuk menunjukkan rumah seseorang.
 *
 * Menyimpan lokasi presisi di aplikasi keamanan akan menciptakan riwayat
 * pergerakan pengguna — persis jenis data yang aplikasi ini ada untuk
 * melindunginya. Jangan naikkan presisinya tanpa alasan yang sangat kuat.
 */
@Entity(tableName = "threat_locations")
data class ThreatLocation(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val latitude: Double,
    val longitude: Double,
    /** Waktu kejadian, epoch milidetik. */
    val timestamp: Long = System.currentTimeMillis(),
    /** PHISHING, JUDOL, SCAM_MESSAGE, FRAUD_CALL — lihat MapCategory. */
    val crimeType: String,
    /** 0..1, dari keyakinan deteksi. */
    val severity: Float,
    /** Chrome, WhatsApp, SMS, Phone — dari mana ancaman datang. */
    val source: String = "",
    /** Domain atau nomor, dipendekkan. Untuk ditampilkan saat marker disentuh. */
    val label: String = ""
) {
    companion object {
        /**
         * Bulatkan koordinat ke ~1,1 km (2 desimal). Dipanggil SEBELUM
         * menyimpan, jadi lokasi presisi tidak pernah menyentuh disk.
         */
        fun roundForPrivacy(value: Double): Double = Math.round(value * 100.0) / 100.0
    }
}

@Dao
interface ThreatLocationDao {

    @Insert
    fun insert(location: ThreatLocation)

    @Query("SELECT * FROM threat_locations ORDER BY timestamp DESC")
    fun getAll(): List<ThreatLocation>

    /** Untuk filter rentang tanggal di peta. */
    @Query("""
        SELECT * FROM threat_locations
        WHERE timestamp BETWEEN :from AND :to
        ORDER BY timestamp DESC
    """)
    fun getBetween(from: Long, to: Long): List<ThreatLocation>

    @Query("SELECT COUNT(*) FROM threat_locations")
    fun getCount(): Int

    /** Dipakai tombol "Hapus data lokasi" di Pengaturan. */
    @Query("DELETE FROM threat_locations")
    fun deleteAll()
}

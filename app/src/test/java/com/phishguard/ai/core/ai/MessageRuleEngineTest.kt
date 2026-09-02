package com.phishguard.ai.core.ai

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Mengunci perilaku mesin aturan pesan (SMS, WhatsApp, notifikasi chat).
 *
 * Dua arah yang dijaga:
 *  - pesan wajar tidak boleh diperingatkan
 *  - scam bergaya lunak, yang tidak memakai satu pun frasa "kuat", TETAP
 *    tertangkap lewat penumpukan pola lemah
 */
class MessageRuleEngineTest {

    private val provider = TFLiteMessageProvider()

    private fun analisis(teks: String) =
        provider.analyze(AnalysisInput(InputType.MESSAGE, teks, "WhatsApp"))

    @Test
    fun `pesan sehari-hari tidak diperingatkan`() {
        assertFalse(analisis("Halo bu, besok jadi ketemu jam 10 di kantor ya").isThreat)
        assertFalse(analisis("Paket sudah sampai depan pagar, saya taruh di situ").isThreat)
    }

    @Test
    fun `satu frasa lunak saja tidak cukup`() {
        // "install aplikasi" wajar muncul di percakapan normal.
        assertFalse(analisis("Coba install aplikasi Livin biar gampang transfer").isThreat)
        assertFalse(analisis("Nanti saya kirim undangan pernikahan ya").isThreat)
    }

    @Test
    fun `scam gaya lunak khas WhatsApp tertangkap`() {
        // Tanpa perbaikan penumpukan pola lemah, ini lolos total: tidak ada
        // satu pun frasa "kuat" di dalamnya.
        val pesan = "Selamat! Anda mendapat hadiah 100 juta uang tunai. " +
                "Silakan klik link berikut dan install aplikasi untuk klaim."
        val r = analisis(pesan)
        assertTrue("skor=${r.confidence} alasan=${r.reason}", r.isThreat)
    }

    @Test
    fun `frasa kuat tetap tertangkap sendirian`() {
        assertTrue(analisis("Mohon kirim kode otp anda untuk verifikasi").isThreat)
        assertTrue(analisis("Rekening anda diblokir, segera konfirmasi data").isThreat)
        assertTrue(analisis("Silakan unduh apk resmi kurir kami di sini").isThreat)
    }

    @Test
    fun `spam judol yang sengaja dikaburkan tertangkap`() {
        // Kalimat nyata dari laporan pengguna. Sebelum ada normalisasi teks
        // dan JudolWordlist di jalur pesan, ini lolos total.
        val spam = "Klaim Saldo Gratiss tanpa D e p 0\n" +
                "Mahy'0ng ways 3| M4X'W1N | W 'D 3min.\n" +
                "https://wde.la/bu5f44"
        val r = analisis(spam)
        assertTrue("skor=${r.confidence} alasan=${r.reason}", r.isThreat)
    }

    @Test
    fun `varian pengaburan lain juga tertangkap`() {
        assertTrue(analisis("Info 5L0T G4C0R hari ini, D3P0 50rb bonus 100rb, W D cepat").isThreat)
        assertTrue(analisis("s.l.o.t g.a.c.o.r maxwin depo pulsa tanpa potongan bonus").isThreat)
    }

    @Test
    fun `pesan wajar berangka tidak ikut kena normalisasi`() {
        // Normalisasi melipat angka jadi huruf, jadi teks asli harus tetap
        // ikut dinilai — kalau tidak, pesan berisi angka jadi kacau.
        assertFalse(analisis("Tolong transfer 250 ribu ke rekening kemarin ya").isThreat)
        assertFalse(analisis("Meeting jam 10 pagi, ruang 3 lantai 5").isThreat)
        assertFalse(analisis("Harga totalnya 1500000 sudah termasuk ongkir").isThreat)
    }

    @Test
    fun `URL meniru bank di dalam pesan tertangkap`() {
        assertTrue(analisis("Cek saldo di bca-verifikasi.vercel.app sekarang").isThreat)
    }

    @Test
    fun `spam yang seluruh katanya dikaburkan tertangkap`() {
        // Dilaporkan lolos: setelah normalisasi tak tersisa satu pun kata
        // kunci ("mimpi 88" jadi "mimpi b", "gacor" tersebar jadi "gha c-
        // 0r"), dan "bit.ly/..." tidak dikenali urlPattern sebagai tautan.
        // Skornya nol, pesan dinyatakan aman.
        val pesan = "c4r1 d1 g00gl3 r3sm1 mimpi 88 " +
                "m*h jng lagl gha c- 0r lh0 " +
                "ada j'g k0m lsl har!an " +
                "bit.ly/mp8-89f6n-29"
        assertTrue(analisis(pesan).isThreat)
    }

    @Test
    fun `gaya menulis leetspeak tanpa tautan tetap aman`() {
        // Pengaburan padat saja tidak memvonis — harus ada tautan, karena
        // tautan itulah tujuan seluruh pesan spam.
        assertFalse(analisis("n1c3 sh0t br0 g4m3 nya seru b4ng tadi m4l4m").isThreat)
    }
}

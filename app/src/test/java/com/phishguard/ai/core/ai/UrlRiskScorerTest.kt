package com.phishguard.ai.core.ai

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Kunci perilaku UrlRiskScorer. Fokusnya dua arah:
 *  - situs normal TIDAK boleh diblokir (kasus false-positive versi lama)
 *  - pola phishing nyata TETAP tertangkap
 */
class UrlRiskScorerTest {

    private val official = setOf("bca.co.id", "klikbca.com", "bri.co.id", "tokopedia.com")
    private val brands = mapOf(
        "bca" to setOf("bca.co.id", "klikbca.com"),
        "klikbca" to setOf("klikbca.com"),
        "bri" to setOf("bri.co.id"),
        "tokopedia" to setOf("tokopedia.com"),
        "dana" to setOf("dana.id")
    )

    private fun verdict(url: String, pageText: String = "") =
        UrlRiskScorer.score(url, official, brands, pageText)

    private fun assertLevel(expected: UrlRiskScorer.Level, url: String, pageText: String = "") {
        val v = verdict(url, pageText)
        assertEquals("$url → skor ${"%.2f".format(v.score)} (${v.reason})", expected, v.level)
    }

    @Test
    fun `domain resmi tidak terblokir`() {
        assertLevel(UrlRiskScorer.Level.SAFE, "https://klikbca.com/")
        assertLevel(UrlRiskScorer.Level.SAFE, "https://www.bri.co.id/")
    }

    // ── Regresi false-positive ──────────────────────────────────────────
    // Dipulihkan setelah sempat terhapus pada penggabungan. Perilaku yang
    // dijaga di sini adalah alasan skoring dibuat berbobot; tanpa test ini
    // tidak ada yang menahan kalau ambangnya bergeser lagi.

    @Test
    fun `halaman login di situs biasa bukan phishing`() {
        // Versi lama: langsung blokir 0,88 hanya karena kata "login" di path.
        assertLevel(UrlRiskScorer.Level.SAFE, "https://situskampus.ac.id/login")
        assertLevel(UrlRiskScorer.Level.SAFE, "https://myapp.com/account/update")
    }

    @Test
    fun `domain multi-kata bertanda hubung wajar`() {
        // Versi lama: 2 tanda hubung → blokir 0,62.
        assertLevel(UrlRiskScorer.Level.SAFE, "https://toko-kopi-enak.com")
        assertLevel(UrlRiskScorer.Level.SAFE, "https://the-blackbird-cafe.com/menu")
    }

    @Test
    fun `kata biasa yang memuat nama brand tidak dianggap peniruan`() {
        // Versi lama: substring bebas → "bri" cocok ke "bridge", "dana" ke "cendana".
        assertLevel(UrlRiskScorer.Level.SAFE, "https://bridge.com")
        assertLevel(UrlRiskScorer.Level.SAFE, "https://cendana-catering.co.id")
        assertTrue(!UrlRiskScorer.brandMatches("bridge.com", "bri"))
        assertTrue(!UrlRiskScorer.brandMatches("fabrics.co.id", "bri"))
    }

    @Test
    fun `TLD niaga populer tidak otomatis berbahaya`() {
        assertLevel(UrlRiskScorer.Level.SAFE, "https://batikpekalongan.shop")
        assertLevel(UrlRiskScorer.Level.SAFE, "https://beritabaru.online/politik")
    }

    @Test
    fun `satu sinyal lemah tidak pernah cukup untuk memblokir`() {
        val v = verdict("https://tokobaru.xyz/login")
        assertTrue("skor=${v.score}", v.level != UrlRiskScorer.Level.DANGEROUS)
    }

    @Test
    fun `peniruan brand dengan afiks tertangkap`() {
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "http://klikbca-verifikasi.tk/login")
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "https://bca-mobile.vercel.app/akun")
        assertTrue(UrlRiskScorer.brandMatches("bankbri-online.xyz", "bri"))
        assertTrue(UrlRiskScorer.brandMatches("bca123.xyz", "bca"))
    }

    @Test
    fun `satu istilah judi ambigu tidak memblokir situs sah`() {
        // "slot" dan "toto" juga nama usaha sah. Satu istilah ambigu hanya
        // boleh memicu pemeriksaan, bukan vonis.
        assertLevel(UrlRiskScorer.Level.SUSPICIOUS, "https://slotcarshop.com")
        assertEquals(1, JudolWordlist.countAmbiguousSignals("slotcarshop.com"))
    }

    @Test
    fun `dua istilah judi ambigu tetap diblokir`() {
        // Domain judol asli menumpuk istilah, jadi tetap tertangkap.
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "https://totoslot88.com")
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "https://rtpslotgacor.net")
    }

    @Test
    fun `domain benign besar tidak terblokir`() {
        assertLevel(UrlRiskScorer.Level.SAFE, "https://google.com/search?q=slot+gacor")
    }

    @Test
    fun `brand hijack tertangkap`() {
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "https://bca-login.vercel.app")
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "https://klikbca-verify.com/login")
    }

    @Test
    fun `typosquat brand panjang tertangkap`() {
        assertTrue(UrlRiskScorer.brandMatches("tokopedla.com", "tokopedia"))
    }

    @Test
    fun `alamat IP mentah plus brand di path tertangkap`() {
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "http://45.11.23.9/bca/login")
    }

    @Test
    fun `domain judi online tertangkap`() {
        assertLevel(UrlRiskScorer.Level.DANGEROUS, "https://slotgacor88.xyz")
    }

    @Test
    fun `konten judi pada domain netral tertangkap`() {
        val judol = "Situs slot gacor maxwin bonus new member deposit pulsa tanpa potongan " +
                "rtp live scatter olympus jackpot terbesar daftar sekarang"
        val v = verdict("https://halaman-promo.com", judol)
        assertTrue("skor=${v.score} (${v.reason})", v.level != UrlRiskScorer.Level.SAFE)
    }

    @Test
    fun `konten judi kuat jadi DANGEROUS langsung bukan SUSPICIOUS`() {
        val judol = "Situs slot gacor maxwin bonus new member deposit pulsa tanpa potongan " +
                "rtp live scatter olympus jackpot terbesar daftar sekarang"
        assertEquals(UrlRiskScorer.Level.DANGEROUS, verdict("https://halaman-promo.com", judol).level)
    }

    @Test
    fun `domain bermuatan istilah judi jadi DANGEROUS langsung`() {
        assertEquals(UrlRiskScorer.Level.DANGEROUS, verdict("https://juragankoin99-totogacor.net").level)
        assertEquals(UrlRiskScorer.Level.DANGEROUS, verdict("https://slot88maxwin.xyz").level)
    }

    @Test
    fun `isi halaman tetap diperiksa walau domain punya satu istilah ambigu`() {
        // Dulu berada di rantai else-if, jadi domain dengan satu istilah
        // ambigu tidak pernah diperiksa isinya — padahal justru itu yang
        // paling butuh konfirmasi dari konten.
        val judol = "slot gacor maxwin rtp live scatter bonus new member " +
                "deposit pulsa jackpot terbesar daftar sekarang"
        assertEquals(
            UrlRiskScorer.Level.DANGEROUS,
            verdict("https://totoharian.com", judol).level
        )
    }

    @Test
    fun `situs judol tanpa kata kunci di domain tertangkap lewat isi halaman`() {
        // Kasus nyata dari log perangkat: coy99win.com, aboutcoy999.com —
        // nama domainnya bersih, isinya jelas judol.
        val judol = "Situs slot gacor terpercaya rtp maxwin bonus new member " +
                "deposit tanpa potongan scatter jackpot daftar sekarang"
        assertEquals(
            UrlRiskScorer.Level.DANGEROUS,
            verdict("https://coy99win.com/home?register", judol).level
        )
    }

    @Test
    fun `registrable domain sadar ccTLD dua tingkat`() {
        assertEquals("bca.co.id", UrlRiskScorer.registrableDomain("m.klikbca.bca.co.id"))
        assertEquals("contoh.com", UrlRiskScorer.registrableDomain("a.b.contoh.com"))
    }
}
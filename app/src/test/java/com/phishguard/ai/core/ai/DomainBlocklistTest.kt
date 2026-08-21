package com.phishguard.ai.core.ai

import org.junit.Assert.assertArrayEquals
import org.junit.Test

/**
 * Uji vektor silang Python ↔ Kotlin.
 *
 * Aset blocklist.bloom dibangun oleh tools/build_blocklist.py. Kalau
 * perhitungan indeks di kedua sisi menyimpang sedikit saja, aset 9,4 MB itu
 * berhenti mencocokkan apa pun — TANPA error, tanpa crash, hanya deteksi
 * yang diam-diam mati. Nilai di bawah dihasilkan langsung oleh skrip Python
 * tersebut, jadi test ini yang menahannya.
 */
class DomainBlocklistTest {

    /**
     * Parameter berskala nyata (~4,1 juta domain, FPR 0,01%). Nilai m aset
     * sesungguhnya bergeser tiap kali blocklist dibangun ulang, jadi di sini
     * dipatok — yang diuji kesepakatan ALGORITMA, bukan isi aset.
     */
    private val m = 78_797_176L
    private val k = 13

    @Test
    fun `indeks cocok dengan generator Python untuk domain biasa`() {
        assertArrayEquals(
            longArrayOf(
                3560686, 19301528, 74095602, 50092500, 26089398, 2086296,
                17827138, 72621212, 48618110, 24615008, 40355850, 16352748,
                71146822
            ),
            DomainBlocklist.indicesFor("contoh.com", m, k)
        )
    }

    @Test
    fun `indeks cocok untuk domain judi`() {
        assertArrayEquals(
            longArrayOf(
                3259449, 24078787, 5844893, 26664231, 47483569, 29249675,
                50069013, 70888351, 52654457, 73473795, 15495957, 76059239,
                18081401
            ),
            DomainBlocklist.indicesFor("slotgacor88.xyz", m, k)
        )
    }

    @Test
    fun `indeks cocok untuk domain peniru bank`() {
        assertArrayEquals(
            longArrayOf(
                5538357, 60348857, 36362181, 12375505, 67186005, 43199329,
                19212653, 74023153, 50036477, 26049801, 2063125, 56873625,
                32886949
            ),
            DomainBlocklist.indicesFor("klikbca-verifikasi.tk", m, k)
        )
    }

    @Test
    fun `parameter kecil juga cocok`() {
        assertArrayEquals(longArrayOf(614, 32, 474), DomainBlocklist.indicesFor("contoh.com", 1024L, 3))
        assertArrayEquals(longArrayOf(129, 253, 377), DomainBlocklist.indicesFor("bca.co.id", 1024L, 3))
    }
}

package com.phishguard.ai.core.ai

/**
 * Sliding Window Memory untuk analisis voice phishing real-time.
 *
 * Mengelola buffer transkripsi dengan mekanisme sliding window
 * agar resource tetap efisien selama panggilan panjang.
 *
 * Cara penggunaan:
 *   1. speech-to-text engine menghasilkan transkripsi
 *   2. addTranscription(text) → tambahkan ke buffer
 *   3. getCurrentWindow() → ambil window terkini untuk analisis AI
 *   4. clear() → reset saat panggilan selesai
 */
class SlidingWindowMemory(
    private val maxWindowSize: Int = 500,   // Maksimal karakter per window
    private val overlapSize: Int = 100      // Overlap antara window berurutan
) {
    private val fullHistory = StringBuilder()
    private var windowStart = 0

    /**
     * Tambahkan transkripsi baru ke buffer.
     */
    fun addTranscription(text: String) {
        if (text.isBlank()) return
        if (fullHistory.isNotEmpty()) fullHistory.append(" ")
        fullHistory.append(text)

        // Geser window jika sudah melebihi max
        if (fullHistory.length - windowStart > maxWindowSize) {
            windowStart = fullHistory.length - maxWindowSize + overlapSize
            if (windowStart < 0) windowStart = 0
        }
    }

    /**
     * Ambil current window untuk analisis AI.
     * Berisi teks terkini dengan overlap dari window sebelumnya.
     */
    fun getCurrentWindow(): String {
        if (fullHistory.isEmpty()) return ""
        return fullHistory.substring(windowStart)
    }

    /**
     * Ambil seluruh history transkripsi (untuk logging/konteks).
     */
    fun getFullHistory(): String = fullHistory.toString()

    /**
     * Total karakter yang sudah ditranskripsi.
     */
    fun getTotalLength(): Int = fullHistory.length

    /**
     * Jumlah window yang sudah diproses.
     */
    fun getWindowCount(): Int {
        if (fullHistory.isEmpty()) return 0
        return ((fullHistory.length - overlapSize) / (maxWindowSize - overlapSize)) + 1
    }

    /**
     * Reset saat panggilan selesai.
     */
    fun clear() {
        fullHistory.clear()
        windowStart = 0
    }
}

package com.phishguard.ai.core.tts

import android.content.Context
import android.speech.tts.TextToSpeech
import android.util.Log
import java.util.Locale

/**
 * MODULE TEXT-TO-SPEECH (TTS)
 * 
 * Modul ini sudah siap pakai untuk mengucap kalimat peringatan melalui speaker.
 * Tim lain tinggal memanggil TextToSpeechEngine.speak("Awas Phishing!")
 */
class TextToSpeechEngine(context: Context) : TextToSpeech.OnInitListener {
    private var tts: TextToSpeech? = null
    private var isReady = false
    private val TAG = "TTSEngine"

    init {
        tts = TextToSpeech(context, this)
    }

    override fun onInit(status: Int) {
        if (status == TextToSpeech.SUCCESS) {
            val result = tts?.setLanguage(Locale("id", "ID")) // Indonesia
            if (result == TextToSpeech.LANG_MISSING_DATA || result == TextToSpeech.LANG_NOT_SUPPORTED) {
                Log.e(TAG, "Bahasa Indonesia tidak didukung atau tidak ditemukan.")
                // Fallback ke bahasa inggris
                tts?.setLanguage(Locale.US)
            } else {
                isReady = true
                Log.d(TAG, "TTS Siap digunakan.")
            }
        } else {
            Log.e(TAG, "Gagal menginisialisasi TextToSpeech.")
        }
    }

    fun speak(text: String) {
        if (isReady) {
            tts?.speak(text, TextToSpeech.QUEUE_FLUSH, null, null)
        } else {
            Log.w(TAG, "TTS Belum siap, tidak bisa mengucapkan: $text")
        }
    }

    fun shutdown() {
        tts?.stop()
        tts?.shutdown()
    }
}

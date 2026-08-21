package com.phishguard.ai.core.ai

import android.content.Context
import android.content.Intent
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Build
import android.os.Bundle
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import android.util.Log
import kotlin.concurrent.thread

/**
 * Call Fraud Detector — Production-Ready Voice Phishing Analysis.
 *
 * IMPLEMENTASI:
 * - Android SpeechRecognizer API (built-in, offline/online)
 * - Real-time continuous speech recognition
 * - SlidingWindowMemory untuk buffer transkripsi
 * - AnalysisPipeline untuk deteksi fraud pattern
 *
 * INTEGRASI:
 * - Dipanggil oleh CallMonitorService ketika pengguna menerima telepon.
 * - Jika terdeteksi penipuan, callback onFraudDetected dipanggil.
 */
class CallFraudDetector(private val context: Context) {

    private val TAG = "CallFraudDetector"
    private var isAnalyzing = false
    private val pipeline = AnalysisPipeline(context)
    private val slidingWindow = SlidingWindowMemory()

    // Speech recognition components
    private var speechRecognizer: SpeechRecognizer? = null
    private var recognizerIntent: Intent? = null
    private var audioRecord: AudioRecord? = null
    private var audioThread: Thread? = null

    /**
     * Callback ketika penipuan terdeteksi dalam panggilan.
     */
    var onFraudDetected: ((confidence: Float, reason: String) -> Unit)? = null

    /**
     * Callback untuk partial transcription (real-time feedback).
     */
    var onPartialTranscription: ((text: String) -> Unit)? = null

    /**
     * Mulai menganalisis panggilan dengan Speech-to-Text.
     */
    fun startAnalyzing() {
        if (isAnalyzing) return
        if (!SpeechRecognizer.isRecognitionAvailable(context)) {
            Log.e(TAG, "Speech recognition not available on this device")
            return
        }

        isAnalyzing = true
        slidingWindow.clear()
        Log.d(TAG, "Started call fraud analysis with STT")

        // Initialize Speech Recognizer
        speechRecognizer = SpeechRecognizer.createSpeechRecognizer(context)
        recognizerIntent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, "id-ID") // Indonesian
            putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, true)
            putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 1)
            putExtra(RecognizerIntent.EXTRA_SPEECH_INPUT_COMPLETE_SILENCE_LENGTH_MILLIS, 2000)
            putExtra(RecognizerIntent.EXTRA_SPEECH_INPUT_POSSIBLY_COMPLETE_SILENCE_LENGTH_MILLIS, 2000)
        }

        speechRecognizer?.setRecognitionListener(object : RecognitionListener {
            override fun onReadyForSpeech(params: Bundle?) {
                Log.d(TAG, "STT ready for speech")
            }

            override fun onBeginningOfSpeech() {
                Log.d(TAG, "STT detected speech start")
            }

            override fun onRmsChanged(rmsdB: Float) {
                // Audio level monitoring (optional)
            }

            override fun onBufferReceived(buffer: ByteArray?) {
                // Raw audio buffer (optional processing)
            }

            override fun onEndOfSpeech() {
                Log.d(TAG, "STT end of speech")
            }

            override fun onError(error: Int) {
                val errorMsg = when (error) {
                    SpeechRecognizer.ERROR_AUDIO -> "Audio recording error"
                    SpeechRecognizer.ERROR_CLIENT -> "Client side error"
                    SpeechRecognizer.ERROR_INSUFFICIENT_PERMISSIONS -> "Insufficient permissions"
                    SpeechRecognizer.ERROR_NETWORK -> "Network error"
                    SpeechRecognizer.ERROR_NETWORK_TIMEOUT -> "Network timeout"
                    SpeechRecognizer.ERROR_NO_MATCH -> "No speech match"
                    SpeechRecognizer.ERROR_RECOGNIZER_BUSY -> "Recognition service busy"
                    SpeechRecognizer.ERROR_SERVER -> "Server error"
                    SpeechRecognizer.ERROR_SPEECH_TIMEOUT -> "No speech input"
                    else -> "Unknown error: $error"
                }
                Log.w(TAG, "STT error: $errorMsg")

                // Restart recognition if still analyzing (continuous mode)
                if (isAnalyzing && error != SpeechRecognizer.ERROR_INSUFFICIENT_PERMISSIONS) {
                    android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                        if (isAnalyzing) {
                            speechRecognizer?.startListening(recognizerIntent)
                        }
                    }, 500)
                }
            }

            override fun onResults(results: Bundle?) {
                val matches = results?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
                if (!matches.isNullOrEmpty()) {
                    val transcription = matches[0]
                    Log.d(TAG, "STT result: $transcription")
                    addTranscription(transcription)
                }

                // Restart recognition for continuous capture
                if (isAnalyzing) {
                    android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                        if (isAnalyzing) {
                            speechRecognizer?.startListening(recognizerIntent)
                        }
                    }, 100)
                }
            }

            override fun onPartialResults(partialResults: Bundle?) {
                val matches = partialResults?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
                if (!matches.isNullOrEmpty()) {
                    val partial = matches[0]
                    Log.v(TAG, "STT partial: $partial")
                    onPartialTranscription?.invoke(partial)
                }
            }

            override fun onEvent(eventType: Int, params: Bundle?) {
                // Reserved for future use
            }
        })

        // Start listening
        try {
            speechRecognizer?.startListening(recognizerIntent)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start speech recognition", e)
            isAnalyzing = false
        }
    }

    /**
     * Feed transkripsi baru dari STT engine.
     * Otomatis di-buffer di SlidingWindowMemory dan dianalisis.
     */
    fun addTranscription(text: String) {
        if (!isAnalyzing || text.isBlank()) return

        slidingWindow.addTranscription(text)
        val currentWindow = slidingWindow.getCurrentWindow()

        Log.d(TAG, "Window buffer: ${currentWindow.take(150)}... (${currentWindow.length} chars)")

        // Analyze current window
        pipeline.analyzeVoice(currentWindow) { result ->
            if (result.isThreat && result.confidence >= 0.6f) {
                Log.w(TAG, "🚨 FRAUD DETECTED! Confidence: ${result.confidence}, Reason: ${result.reason}")
                onFraudDetected?.invoke(result.confidence, result.reason)
            }
        }
    }

    /**
     * Berhenti menganalisis.
     */
    fun stopAnalyzing() {
        if (!isAnalyzing) return

        isAnalyzing = false

        // Stop speech recognizer
        try {
            speechRecognizer?.stopListening()
            speechRecognizer?.cancel()
            speechRecognizer?.destroy()
            speechRecognizer = null
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping speech recognizer", e)
        }

        // Stop audio record thread
        audioRecord?.stop()
        audioRecord?.release()
        audioRecord = null
        audioThread?.interrupt()
        audioThread = null

        val totalChars = slidingWindow.getTotalLength()
        Log.d(TAG, "Stopped call fraud analysis. Total transcribed: $totalChars chars")

        if (totalChars > 0) {
            val fullTranscript = slidingWindow.getCurrentWindow()
            Log.d(TAG, "Full transcript: $fullTranscript")
        }

        slidingWindow.clear()
    }

    /**
     * Menganalisis teks transkripsi (backward-compatible method).
     */
    fun analyzeTranscription(transcription: String): Float {
        Log.d(TAG, "Analyzing transcription: ${transcription.take(100)}...")

        var resultConfidence = 0.0f
        pipeline.analyzeVoice(transcription) { result ->
            resultConfidence = if (result.isThreat) result.confidence else 0.0f
        }
        return resultConfidence
    }

    /**
     * Get current transcription buffer.
     */
    fun getCurrentTranscription(): String {
        return slidingWindow.getCurrentWindow()
    }

    fun release() {
        stopAnalyzing()
        pipeline.release()
    }
}

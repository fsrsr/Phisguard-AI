# Voice Phishing Detection - Production Implementation

## Overview
Implementasi production-ready untuk deteksi penipuan telepon (voice phishing) menggunakan Speech-to-Text real-time dan analisis pola fraud berbasis AI.

## Technology Stack
- **Speech Recognition**: Android SpeechRecognizer API (built-in, offline/online capable)
- **Language**: Indonesian (id-ID)
- **Pattern Analysis**: Rule-based + keyword matching dengan context awareness
- **Buffer**: SlidingWindowMemory untuk continuous transcription

## Key Features

### 1. Real-time Speech-to-Text
- Continuous speech recognition selama panggilan berlangsung
- Partial results untuk feedback real-time
- Auto-restart pada error (kecuali permission error)
- Silence detection (2 detik)

### 2. Advanced Fraud Pattern Detection
Deteksi berbasis kombinasi keyword dengan scoring contextual:

**High-Risk Combinations (0.50)**:
- Financial terms + Credentials (transfer + OTP/PIN)

**Authority Impersonation (0.45)**:
- Authority figure + Threats (polisi + denda/blokir)

**Social Engineering (0.40)**:
- Family emergency keywords (keluarga + kecelakaan + rumah sakit)

**Urgency Tactics (0.25)**:
- Time pressure dengan multiple keywords

**Prize Scams (0.20)**:
- Lottery/hadiah keywords

### 3. Keyword Categories (70+ keywords)
- Financial: transfer, rekening, saldo, mutasi
- Credentials: otp, pin, password, cvv
- Authority: polisi, pajak, ojk, bank indonesia
- Threats: denda, blokir, ditangkap, sanksi
- Social: keluarga, anak anda, kecelakaan
- Package scams: paket, jne, j&t, sicepat
- Investment scams: profit, binary option
- Government aid: bansos, subsidi

### 4. Alert System
- Real-time notification saat fraud terdeteksi (confidence >= 60%)
- High-priority notification dengan vibration
- Log lengkap di Activity tab
- Full transcript tersimpan setelah panggilan berakhir

## Implementation Files

### Modified Files
1. `CallFraudDetector.kt` - STT engine + analysis coordinator
2. `DefaultRuleProvider.kt` - Enhanced fraud pattern detection
3. `CallMonitorService.kt` - Service integration + notifications

### Key Components

**CallFraudDetector**:
```kotlin
fun startAnalyzing() // Start STT + analysis
fun stopAnalyzing() // Stop and save transcript
fun addTranscription(text: String) // Feed text to analyzer
fun getCurrentTranscription(): String // Get full buffer
```

**Callbacks**:
```kotlin
onFraudDetected: (confidence: Float, reason: String) -> Unit
onPartialTranscription: (text: String) -> Unit
```

## Permissions Required
- `android.permission.RECORD_AUDIO` - Already declared in AndroidManifest.xml
- `android.permission.READ_PHONE_STATE` - Already declared

## Flow Diagram
```
Call Ringing → CALL_STATE_OFFHOOK → Start STT
    ↓
Continuous Recognition Loop
    ↓
onResults() → addTranscription() → SlidingWindowMemory
    ↓
AnalysisPipeline.analyzeVoice()
    ↓
DefaultRuleProvider.analyzeVoice() → Pattern Matching
    ↓
If fraud detected (>= 0.6 confidence)
    ↓
onFraudDetected callback → Show notification + Log
    ↓
CALL_STATE_IDLE → Stop STT → Save transcript
```

## Testing Scenarios

### Test Case 1: Financial + Credential Scam
**Input**: "Ini dari Bank Indonesia. Rekening Anda akan diblokir. Segera berikan kode OTP untuk verifikasi."
**Expected**: Fraud detected (>= 0.9 confidence)
**Patterns**: Authority + Threat + Financial + Credentials + Urgency

### Test Case 2: Family Emergency Scam
**Input**: "Pak, anak Anda kecelakaan. Sekarang di rumah sakit. Butuh transfer segera untuk operasi darurat."
**Expected**: Fraud detected (>= 0.8 confidence)
**Patterns**: Social Engineering + Financial + Urgency

### Test Case 3: Prize Scam
**Input**: "Selamat! Anda pemenang undian hadiah 100 juta. Klik link untuk klaim hadiah."
**Expected**: Fraud detected (>= 0.6 confidence)
**Patterns**: Prize keywords

### Test Case 4: Normal Conversation
**Input**: "Halo, saya mau tanya produk yang dijual di toko Anda."
**Expected**: Safe (<0.6 confidence)

## Limitations

1. **STT Accuracy**: Tergantung kualitas audio dan aksen
2. **Network**: Online recognition butuh koneksi (fallback ke offline jika tersedia)
3. **Language**: Optimized untuk Bahasa Indonesia
4. **False Positives**: Percakapan legitimate yang kebetulan mengandung keyword finansial
5. **Device Support**: Tidak semua device support SpeechRecognizer

## Future Improvements

1. **Machine Learning Model**: Ganti rule-based dengan TFLite/ONNX model
2. **Multi-language**: Support English, regional languages
3. **Voice Biometrics**: Detect synthetic/deepfake voices
4. **Call Recording**: Optional recording untuk evidence
5. **Cloud Sync**: Share fraud patterns via Firebase
6. **Auto-block**: Automatic call termination pada high-confidence threats

## Status
✅ Production-ready (rule-based detection)
⚠️  Recommended: Integrate ML model untuk akurasi lebih tinggi

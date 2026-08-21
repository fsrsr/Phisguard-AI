# PhishGuard AI ("Save Me") — Panduan Integrasi Tim

Dokumen ini berisi panduan untuk **semua tim** mengenai struktur proyek dan cara mengintegrasikan modul masing-masing ke dalam aplikasi Android.

## Arsitektur Aplikasi

```
📱 UI Layer (Programmer)
├── MainActivity + BottomNavigationView
├── DashboardFragment — Status, stats, recent threats
├── ProtectionFragment — App selector (WA, Telegram, dll)
├── ActivityFragment — Activity log + filter
└── SettingsFragment — Accessibility, TTS, notifications

⚙️ Service Layer (Programmer — SELESAI)
├── PhishGuardService — Accessibility Service, multi-app monitoring
├── SmsReceiver — BroadcastReceiver untuk SMS masuk
└── CallMonitorService — ForegroundService untuk call monitoring

🤖 AI Layer (Tim AI — BOILERPLATE)
├── PhishingDetector — Analisis URL phishing
├── CallFraudDetector — Deteksi telepon penipuan
└── MessageAnalyzer — Analisis pesan/SMS

🔒 Security Layer (Tim Security — BOILERPLATE)
├── ThreatAnalyzer — Unified threat analysis
├── BlacklistManager — Database blacklist domain/IP
└── SSLValidator — Validasi sertifikat SSL/TLS

🌐 Network Layer (BOILERPLATE)
└── ApiClient — HTTP client (GET/POST)
```

---

## 1. Tim AI (`core/ai/`)

### PhishingDetector.kt
- **Apa**: Evaluasi apakah URL phishing atau bukan
- **Dipanggil oleh**: `PhishGuardService.onAccessibilityEvent()` saat URL terdeteksi di browser
- **Input**: `url: String`, `sourceApp: String`
- **Output**: `onResult(isPhishing: Boolean, confidence: Float, reason: String)`
- **TODO**: Ganti logika dummy dengan model AI (TFLite/ONNX/API)

### CallFraudDetector.kt
- **Apa**: Deteksi telepon penipuan secara real-time
- **Dipanggil oleh**: `CallMonitorService` saat panggilan dimulai
- **Cara kerja**: `startAnalyzing()` dipanggil saat call dimulai, `stopAnalyzing()` saat selesai
- **Callback**: Set `onFraudDetected` untuk mengirim alert
- **TODO**: Integrasikan STT + NLP model untuk analisis percakapan

### MessageAnalyzer.kt
- **Apa**: Deteksi link phishing dan pola penipuan dalam pesan teks
- **Dipanggil oleh**: `SmsReceiver` (SMS) dan `PhishGuardService` (chat apps)
- **Input**: `message: String`, `sourceApp: String`
- **Output**: `onResult(isSuspicious: Boolean, confidence: Float, reason: String)`
- **TODO**: Implementasikan NLP model untuk analisis pesan

---

## 2. Tim Security (`core/security/`)

### ThreatAnalyzer.kt
- **Apa**: Entry point utama untuk analisis keamanan
- **Cara pakai**: Bisa dipanggil bersamaan dengan `PhishingDetector` untuk cross-check
- **TODO**: Kombinasikan `BlacklistManager` dan `SSLValidator` di sini

### BlacklistManager.kt
- **Apa**: Kelola database domain/IP yang sudah diketahui berbahaya
- **TODO**: Buat database lokal (SQLite/Room), integrasikan PhishTank/Google Safe Browsing

### SSLValidator.kt
- **Apa**: Validasi sertifikat SSL/TLS domain
- **PENTING**: Harus dipanggil di background thread!
- **TODO**: Implementasikan certificate chain validation, expiry check, self-signed detection

---

## 3. Tim Network (`core/network/`)

### ApiClient.kt
- **Apa**: Generic HTTP client dengan `get()` dan `post()` methods
- **PENTING**: Semua call sudah di-wrap dalam `thread { }` — aman dipanggil dari mana saja
- **TODO**: Ganti endpoint dummy, tambahkan auth jika perlu

---

## 4. Modul Siap Pakai

### TextToSpeechEngine.kt (`core/tts/`)
**Sudah 100% jadi.** Panggil `TextToSpeechEngine(context).speak("Awas phishing!")` untuk peringatan suara.

### AppPreferences.kt (`data/`)
**Sudah jadi.** Wrapper SharedPreferences — cek setting user:
```kotlin
val prefs = AppPreferences(context)
if (prefs.monitorWhatsApp) { ... }
if (prefs.ttsEnabled) { ttsEngine.speak("Warning!") }
```

---

## Cara Mengirim Log ke UI

Dari mana saja, kirim broadcast:
```kotlin
val intent = Intent("com.example.ai_project_singapore.LOG_UPDATE")
intent.putExtra("message", "Pesan yang muncul di log")
intent.putExtra("source", "Chrome")  // Nama sumber
intent.putExtra("type", "PHISHING")  // SAFE, PHISHING, CALL, atau SYSTEM
context.sendBroadcast(intent)
```

Log akan muncul otomatis di **Dashboard** (recent threats) dan **Activity** tab.

---

**Selamat Hacking! 🚀**

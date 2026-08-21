# ─────────────────────────────────────────────────────────────────────────
# Aturan ProGuard PhishGuard
#
# PENTING: seluruh aturan di berkas ini sebelumnya menunjuk paket lama
# `com.example.ai_project_singapore` yang sudah tidak ada sejak refactor ke
# `com.phishguard.ai`. Akibatnya tidak satu pun berlaku, dan build release
# akan menutup diri sendiri saat dibuka: AppIntegrityChecker mencari
# kelasnya lewat Class.forName, kelas itu tereobfuscate, pemeriksaan gagal,
# lalu MainActivity menampilkan dialog "aplikasi telah dimodifikasi".
# ─────────────────────────────────────────────────────────────────────────

# Kelas yang dicari lewat nama saat runtime (AppIntegrityChecker.criticalClasses).
# Nama-nama ini TIDAK boleh berubah, atau pemeriksaan integritas gagal.
-keep class com.phishguard.ai.PhishGuardService { *; }
-keep class com.phishguard.ai.core.security.AppIntegrityChecker { *; }
-keep class com.phishguard.ai.receiver.SmsReceiver { *; }
-keep class com.phishguard.ai.service.CallMonitorService { *; }

# Komponen yang dirujuk AndroidManifest lewat nama.
-keep class com.phishguard.ai.MainActivity { *; }
-keep class com.phishguard.ai.ui.WarningActivity { *; }
-keep class com.phishguard.ai.service.SmsNotificationInterceptorService { *; }

# Kontrak provider AI: ditukar-pasang, jadi bentuknya harus utuh.
-keep interface com.phishguard.ai.core.ai.AIModelProvider { *; }
-keep class com.phishguard.ai.core.ai.AnalysisInput { *; }
-keep class com.phishguard.ai.core.ai.AnalysisResult { *; }
-keep class com.phishguard.ai.core.ai.InputType { *; }
-keep class com.phishguard.ai.core.ai.ThreatCategory { *; }
-keep class com.phishguard.ai.core.ai.LayeredResult { *; }
-keep class com.phishguard.ai.core.ai.ThreatLayer { *; }

# Entity & DAO Room: dipetakan lewat refleksi dari nama field.
-keep class com.phishguard.ai.data.db.** { *; }
-keep class com.phishguard.ai.data.ActivityLogItem { *; }
-keep class com.phishguard.ai.data.ActivityLogItem$LogType { *; }

# Firestore memetakan dokumen ke objek lewat nama properti.
-keepclassmembers class com.phishguard.ai.** {
    public <init>();
    public void set*(***);
    public *** get*();
}

# Gson: nama field jadi kunci JSON.
-keep class com.google.gson.** { *; }
-keepclassmembers,allowobfuscation class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# TensorFlow Lite (opsional, dipakai bila model dipasang).
-keep class org.tensorflow.lite.** { *; }
-dontwarn org.tensorflow.**

-keepattributes Signature
-keepattributes *Annotation*
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

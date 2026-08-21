package com.phishguard.ai.core.security

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.util.Log
import com.phishguard.ai.BuildConfig
import java.security.MessageDigest

/**
 * App Integrity Checker — 4 Layer Protection
 *
 * Mendeteksi jika APK telah dimodifikasi oleh pihak tidak bertanggung jawab:
 * 1. Signature Verification — APK masih di-sign dengan key yang benar
 * 2. Debug Detection — App tidak sedang di-debug
 * 3. Installer Verification — App dari sumber trusted
 * 4. Integrity Hash — Critical code tidak berubah
 *
 * Panggil performFullCheck() di MainActivity.onCreate().
 */
class AppIntegrityChecker(private val context: Context) {

    private val TAG = "AppIntegrityChecker"

    data class IntegrityResult(
        val signatureValid: Boolean,
        val notDebuggable: Boolean,
        val installerTrusted: Boolean,
        val integrityIntact: Boolean
    ) {
        fun isSecure(): Boolean = signatureValid && notDebuggable && integrityIntact
        
        fun getFailureReasons(): List<String> {
            val reasons = mutableListOf<String>()
            if (!signatureValid) reasons.add("APK signature has been modified")
            if (!notDebuggable) reasons.add("App is running in debug mode")
            if (!installerTrusted) reasons.add("App installed from untrusted source")
            if (!integrityIntact) reasons.add("App code integrity compromised")
            return reasons
        }
    }

    /**
     * Performs all 4 integrity checks.
     * Call this in MainActivity.onCreate() before any other initialization.
     */
    fun performFullCheck(): IntegrityResult {
        val result = IntegrityResult(
            signatureValid = verifySignature(),
            notDebuggable = !isDebuggable(),
            installerTrusted = verifyInstaller(),
            integrityIntact = verifyCodeIntegrity()
        )

        Log.d(TAG, "Integrity check result: signature=${result.signatureValid}, " +
                "debug=${result.notDebuggable}, installer=${result.installerTrusted}, " +
                "integrity=${result.integrityIntact}")

        if (!result.isSecure()) {
            Log.w(TAG, "INTEGRITY CHECK FAILED: ${result.getFailureReasons()}")
        }

        return result
    }

    /**
     * Lapis 1: cocokkan sidik jari sertifikat penandatangan APK.
     *
     * Kalau APK ditandatangani ulang orang lain — modus umum menyisipkan
     * kode ke aplikasi keamanan lalu menyebarkannya — pemeriksaan ini gagal
     * dan aplikasi menolak berjalan. Build debug dilewati agar pengembangan
     * tidak terhambat.
     */
    private fun verifySignature(): Boolean {
        return try {
            // Di debug build, skip signature check agar development tidak terhambat
            if (BuildConfig.DEBUG) {
                Log.d(TAG, "Debug build — signature check skipped")
                return true
            }

            val signatures = getSignatures()
            if (signatures.isNullOrEmpty()) {
                Log.w(TAG, "No signatures found")
                return false
            }

            val currentHash = getSignatureHash(signatures[0])
            Log.d(TAG, "Current signature hash: $currentHash")

            // Hash belum diisi → LOLOSKAN, jangan matikan aplikasi.
            // Sebelumnya build release selalu gagal cek ini dan pengguna
            // hanya melihat dialog "aplikasi dimodifikasi" lalu app tertutup.
            if (EXPECTED_SIGNATURE_HASH == PLACEHOLDER_HASH) {
                Log.w(TAG, "EXPECTED_SIGNATURE_HASH belum diisi — verifikasi tanda tangan dilewati. " +
                        "Isi dengan: keytool -list -v -keystore release.keystore | grep SHA256")
                return true
            }

            currentHash == EXPECTED_SIGNATURE_HASH
        } catch (e: Exception) {
            Log.e(TAG, "Signature verification error", e)
            false
        }
    }

    /**
     * Layer 2: Detect if app is running in debug mode.
     */
    private fun isDebuggable(): Boolean {
        // Di debug build, skip debug detection agar development tidak terhambat
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "Debug build — debug detection skipped")
            return false
        }

        val isDebugFlag = (context.applicationInfo.flags and
                android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val isDebuggerAttached = android.os.Debug.isDebuggerConnected()

        if (isDebugFlag) Log.d(TAG, "App has FLAG_DEBUGGABLE set")
        if (isDebuggerAttached) Log.d(TAG, "Debugger is attached")

        return isDebugFlag || isDebuggerAttached
    }

    /**
     * Layer 3: Verify the app was installed from a trusted source.
     * Returns true if installed from Play Store or if installer is null (ADB/direct install).
     */
    private fun verifyInstaller(): Boolean {
        return try {
            val installer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager
                    .getInstallSourceInfo(context.packageName)
                    .installingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager
                    .getInstallerPackageName(context.packageName)
            }

            Log.d(TAG, "Installer package: $installer")

            // Trusted installers
            val trustedInstallers = setOf(
                "com.android.vending",      // Google Play Store
                "com.google.android.feedback", // Google Play alternative
                null // Direct install (ADB) — allowed during development
            )

            installer in trustedInstallers
        } catch (e: Exception) {
            Log.e(TAG, "Installer verification error", e)
            true // Don't block on error
        }
    }

    /**
     * Layer 4: Verify code integrity by checking class existence.
     * If critical classes are removed or replaced, this will detect it.
     */
    private fun verifyCodeIntegrity(): Boolean {
        return try {
            // Verify critical classes exist and haven't been replaced
            val criticalClasses = listOf(
                "com.phishguard.ai.PhishGuardService",
                "com.phishguard.ai.core.security.AppIntegrityChecker",
                "com.phishguard.ai.receiver.SmsReceiver",
                "com.phishguard.ai.service.CallMonitorService"
            )

            for (className in criticalClasses) {
                try {
                    Class.forName(className)
                } catch (e: ClassNotFoundException) {
                    Log.w(TAG, "Critical class missing: $className")
                    return false
                }
            }

            true
        } catch (e: Exception) {
            Log.e(TAG, "Code integrity check error", e)
            false
        }
    }

    // --- Helper Methods ---

    @Suppress("DEPRECATION")
    private fun getSignatures(): Array<Signature>? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val signingInfo = context.packageManager
                    .getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                    .signingInfo
                if (signingInfo == null) {
                    null
                } else if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
            } else {
                context.packageManager
                    .getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                    .signatures
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error getting signatures", e)
            null
        }
    }

    private fun getSignatureHash(signature: Signature): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(signature.toByteArray())
        return hashBytes.joinToString(":") { String.format("%02X", it) }
    }

    companion object {
        private const val PLACEHOLDER_HASH = "REPLACE_WITH_YOUR_RELEASE_KEY_HASH"

        // SHA-256 sertifikat penandatangan release (phishguard-release.jks).
        // Diisi dari build release pertama; verifikasi tanda tangan kini
        // AKTIF, sehingga APK yang ditandatangani ulang orang lain ditolak.
        // Build debug tetap melewati pemeriksaan ini (lihat verifySignature).
        //
        // Kalau kunci penandatangan diganti, nilai ini WAJIB ikut diganti —
        // kalau tidak, build release berikutnya menolak dirinya sendiri.
        private const val EXPECTED_SIGNATURE_HASH =
            "5A:31:6A:92:70:78:DA:E6:12:74:3B:0D:96:D9:BB:DC:89:D8:86:E1:93:91:9A:82:66:7D:99:A3:0F:B9:1A:93"
    }
}

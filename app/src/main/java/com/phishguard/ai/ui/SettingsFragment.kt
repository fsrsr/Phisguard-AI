package com.phishguard.ai.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.FileProvider
import androidx.fragment.app.Fragment
import com.phishguard.ai.R
import com.phishguard.ai.core.ui.FloatingCheckManager
import com.phishguard.ai.data.AppPreferences
import com.google.android.material.switchmaterial.SwitchMaterial
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class SettingsFragment : Fragment() {

    private companion object { const val REQ_LOKASI = 3001 }

    /**
     * Peta Pola Ancaman — opt-in penuh. Menyalakannya berarti aplikasi mulai
     * menyimpan perkiraan lokasi tiap ancaman yang diblokir, jadi izinnya
     * diminta di sini dan togglenya baru menyala setelah diberikan.
     */
    private fun siapkanPetaPola(view: View) {
        val p = AppPreferences(requireContext())
        val sw = view.findViewById<SwitchMaterial>(R.id.switchThreatMap)
        sw?.isChecked = p.threatMapEnabled && punyaIzinLokasi()
        sw?.setOnCheckedChangeListener { tampilan, dicentang ->
            if (dicentang && !punyaIzinLokasi()) {
                tampilan.isChecked = false
                p.threatMapEnabled = false
                requestPermissions(arrayOf(android.Manifest.permission.ACCESS_COARSE_LOCATION), REQ_LOKASI)
                return@setOnCheckedChangeListener
            }
            p.threatMapEnabled = dicentang
        }
        view.findViewById<android.view.View>(R.id.btnOpenMap)?.setOnClickListener {
            startActivity(android.content.Intent(requireContext(), ThreatMapActivity::class.java))
        }
        view.findViewById<android.view.View>(R.id.btnClearMap)?.setOnClickListener {
            kotlin.concurrent.thread {
                try {
                    com.phishguard.ai.data.db.PhishingDatabase
                        .getInstance(requireContext().applicationContext)
                        .threatLocationDao().deleteAll()
                } catch (_: Exception) {}
                activity?.runOnUiThread {
                    android.widget.Toast.makeText(context, R.string.map_cleared, android.widget.Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun punyaIzinLokasi(): Boolean =
        androidx.core.content.ContextCompat.checkSelfPermission(
            requireContext(), android.Manifest.permission.ACCESS_COARSE_LOCATION
        ) == android.content.pm.PackageManager.PERMISSION_GRANTED

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<out String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_LOKASI) return
        val ok = grantResults.isNotEmpty() &&
                grantResults[0] == android.content.pm.PackageManager.PERMISSION_GRANTED
        AppPreferences(requireContext()).threatMapEnabled = ok
        view?.findViewById<SwitchMaterial>(R.id.switchThreatMap)?.isChecked = ok
        if (!ok) android.widget.Toast.makeText(context, R.string.map_need_permission, android.widget.Toast.LENGTH_LONG).show()
    }


    private lateinit var prefs: AppPreferences

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_settings, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppPreferences(requireContext())

        // Accessibility Service
        val btnAccessibility = view.findViewById<LinearLayout>(R.id.btnAccessibility)
        btnAccessibility.setOnClickListener {
            val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            startActivity(intent)
        }
        
        // Test SMS Detection Button (for debugging)
        val btnTestSms = view.findViewById<LinearLayout>(R.id.btnTestSms)
        if (btnTestSms != null) {
            android.util.Log.d("SettingsFragment", "Test button found, setting click listener")
            btnTestSms.setOnClickListener {
                android.util.Log.d("SettingsFragment", "Test button clicked!")
                android.widget.Toast.makeText(requireContext(), "Launching SMS test...", android.widget.Toast.LENGTH_SHORT).show()
                
                val testIntent = Intent(requireContext(), WarningActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    putExtra(WarningActivity.EXTRA_PHISHING_URL, "URGENT! Anda menang hadiah 100 juta. Klik: bit.ly/test")
                    putExtra(WarningActivity.EXTRA_REASON, "SMS dari 08123456789 mengandung pola penipuan.\n\nTerdeteksi: kata 'menang', 'hadiah', 'urgent'\nSkor: 95%")
                    putExtra(WarningActivity.EXTRA_SOURCE, "SMS (08123456789)")
                    putExtra("is_sms_mode", true)
                    putExtra("phone_number", "08123456789")
                }
                startActivity(testIntent)
            }
        } else {
            android.util.Log.e("SettingsFragment", "Test button NOT found in layout!")
        }

        // Notifications
        val switchNotifications = view.findViewById<SwitchMaterial>(R.id.switchNotifications)
        switchNotifications.isChecked = prefs.notificationsEnabled
        switchNotifications.setOnCheckedChangeListener { _, checked ->
            prefs.notificationsEnabled = checked
        }

        // TTS
        val switchTts = view.findViewById<SwitchMaterial>(R.id.switchTts)
        switchTts.isChecked = prefs.ttsEnabled
        switchTts.setOnCheckedChangeListener { _, checked ->
            prefs.ttsEnabled = checked
        }

        // Notification Access (SMS/chat interceptor)
        val btnNotifAccess = view.findViewById<LinearLayout>(R.id.btnNotifAccess)
        btnNotifAccess.setOnClickListener {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        }

        // Floating Check Button toggle
        val switchFloatingCheck = view.findViewById<SwitchMaterial>(R.id.switchFloatingCheck)
        val floatingPrefs = requireContext().getSharedPreferences("floating_check", Context.MODE_PRIVATE)
        switchFloatingCheck.isChecked = floatingPrefs.getBoolean("enabled", true)
        switchFloatingCheck.setOnCheckedChangeListener { _, checked ->
            floatingPrefs.edit().putBoolean("enabled", checked).apply()
            if (checked && !android.provider.Settings.canDrawOverlays(requireContext())) {
                // Minta izin overlay
                val intent = Intent(
                    android.provider.Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    android.net.Uri.parse("package:${requireContext().packageName}")
                )
                startActivity(intent)
                Toast.makeText(requireContext(), "Izinkan overlay untuk tombol Check", Toast.LENGTH_LONG).show()
            }
        }

        // Export Activity Log ke CSV (bukti laporan, mis. untuk kepolisian)
        val btnExport = view.findViewById<LinearLayout>(R.id.btnExportLog)
        btnExport.setOnClickListener { exportActivityLog() }
    
        siapkanPetaPola(view)
}

    /**
     * Tulis log aktivitas (SharedPreferences "activity_log") ke CSV di
     * Download/, lalu buka share sheet agar file mudah dikirim.
     * Format per baris: timestamp ISO|message|source|type (CSV-escaped).
     */
    private fun exportActivityLog() {
        val logs = requireContext().getSharedPreferences("activity_log", Context.MODE_PRIVATE)
            .getStringSet("logs", emptySet()) ?: emptySet()

        if (logs.isEmpty()) {
            Toast.makeText(requireContext(), R.string.export_empty, Toast.LENGTH_SHORT).show()
            return
        }

        // CSV header + baris terurut (terbaru dulu)
        val sb = StringBuilder("timestamp,message,source,type\n")
        logs.sortedByDescending { it.substringBefore('|').toLongOrNull() ?: 0L }
            .forEach { entry ->
                val parts = entry.split("|", limit = 4)
                if (parts.size == 4) {
                    sb.append(csv(parts[0])).append(',')
                        .append(csv(parts[1])).append(',')
                        .append(csv(parts[2])).append(',')
                        .append(csv(parts[3])).append('\n')
                }
            }

        val fileName = "phishguard_log_${SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())}.csv"
        val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        val file = File(dir, fileName)
        file.writeText(sb.toString())

        // Share sheet: kirim file ke WhatsApp/Drive/email tanpa izin storage
        val uri = FileProvider.getUriForFile(requireContext(), "${requireContext().packageName}.fileprovider", file)
        val share = Intent(Intent.ACTION_SEND).apply {
            type = "text/csv"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(share, getString(R.string.setting_export)))
        Toast.makeText(requireContext(), getString(R.string.export_success, fileName), Toast.LENGTH_LONG).show()
    }

    /** Escape nilai CSV: bungkus kutip jika mengandung koma/kutip/baris baru. */
    private fun csv(value: String): String {
        val v = value.replace("\"", "\"\"")
        return if (v.any { it == ',' || it == '"' || it == '\n' }) "\"$v\"" else v
    }

    override fun onResume() {
        super.onResume()
        updateAccessibilityStatus()
    }

    private fun updateAccessibilityStatus() {
        val tvStatus = view?.findViewById<TextView>(R.id.tvAccessibilityStatus) ?: return
        if (isServiceEnabled()) {
            tvStatus.text = "Active"
            tvStatus.setTextColor(requireContext().getColor(R.color.success))
        } else {
            tvStatus.text = "Off"
            tvStatus.setTextColor(requireContext().getColor(R.color.error))
        }
    }

    private fun isServiceEnabled(): Boolean {
        val enabledServices = Settings.Secure.getString(
            requireContext().contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
        ) ?: ""
        return enabledServices.contains(requireContext().packageName) &&
                enabledServices.contains("PhishGuardService")
    }
}

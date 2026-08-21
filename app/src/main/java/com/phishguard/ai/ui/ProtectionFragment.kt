package com.phishguard.ai.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.phishguard.ai.R
import com.phishguard.ai.core.InstalledAppDetector
import com.phishguard.ai.data.AppPreferences
import com.google.android.material.switchmaterial.SwitchMaterial

class ProtectionFragment : Fragment() {

    private companion object {
        const val REQ_MIKROFON = 2001
    }

    private lateinit var prefs: AppPreferences

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_protection, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        prefs = AppPreferences(requireContext())

        setupDefaultSwitches(view)
        setupDetectedApps(view)
    }

    /**
     * Setup default hardcoded app monitoring switches.
     */
    private fun setupDefaultSwitches(view: View) {
        val switchWhatsapp = view.findViewById<SwitchMaterial>(R.id.switchWhatsapp)
        val switchTelegram = view.findViewById<SwitchMaterial>(R.id.switchTelegram)
        val switchFacebook = view.findViewById<SwitchMaterial>(R.id.switchFacebook)
        val switchInstagram = view.findViewById<SwitchMaterial>(R.id.switchInstagram)
        val switchChrome = view.findViewById<SwitchMaterial>(R.id.switchChrome)
        val switchCallProtection = view.findViewById<SwitchMaterial>(R.id.switchCallProtection)

        // Load current state
        switchWhatsapp.isChecked = prefs.monitorWhatsApp
        switchTelegram.isChecked = prefs.monitorTelegram
        switchFacebook.isChecked = prefs.monitorFacebook
        switchInstagram.isChecked = prefs.monitorInstagram
        switchChrome.isChecked = prefs.monitorChrome
        switchCallProtection.isChecked = prefs.callProtectionEnabled

        // Nyalakan lagi saat aplikasi dibuka — tapi hanya kalau izinnya
        // masih ada. Tanpa penjagaan ini, toggle yang tersimpan menyala akan
        // memulai service yang pasti gagal, dan aplikasi tidak bisa dibuka
        // sama sekali.
        if (prefs.callProtectionEnabled) {
            if (punyaIzinMikrofon()) {
                startCallService()
            } else {
                prefs.callProtectionEnabled = false
                switchCallProtection.isChecked = false
            }
        }

        // Save on change
        switchWhatsapp.setOnCheckedChangeListener { _, checked -> prefs.monitorWhatsApp = checked }
        switchTelegram.setOnCheckedChangeListener { _, checked -> prefs.monitorTelegram = checked }
        switchFacebook.setOnCheckedChangeListener { _, checked -> prefs.monitorFacebook = checked }
        switchInstagram.setOnCheckedChangeListener { _, checked -> prefs.monitorInstagram = checked }
        switchChrome.setOnCheckedChangeListener { _, checked -> prefs.monitorChrome = checked }
        
        switchCallProtection.setOnCheckedChangeListener { view, checked ->
            if (checked && !punyaIzinMikrofon()) {
                // Android 14+ menolak foreground service mikrofon tanpa izin
                // ini, dan penolakannya berupa crash. Minta izinnya dulu;
                // togglenya baru boleh menyala setelah diberikan.
                view.isChecked = false
                prefs.callProtectionEnabled = false
                mintaIzinMikrofon()
                return@setOnCheckedChangeListener
            }
            prefs.callProtectionEnabled = checked
            if (checked) startCallService() else stopCallService()
        }
    }

    private fun punyaIzinMikrofon(): Boolean =
        ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.RECORD_AUDIO) ==
                PackageManager.PERMISSION_GRANTED

    private fun mintaIzinMikrofon() {
        requestPermissions(arrayOf(Manifest.permission.RECORD_AUDIO), REQ_MIKROFON)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<out String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_MIKROFON) return
        val diberikan = grantResults.isNotEmpty() &&
                grantResults[0] == PackageManager.PERMISSION_GRANTED
        view?.findViewById<SwitchMaterial>(R.id.switchCallProtection)?.isChecked = diberikan
        if (diberikan) {
            prefs.callProtectionEnabled = true
            startCallService()
        }
    }

    private fun startCallService() {
        try {
            val intent = Intent(requireContext(), com.phishguard.ai.service.CallMonitorService::class.java)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                requireContext().startForegroundService(intent)
            } else {
                requireContext().startService(intent)
            }
        } catch (e: Exception) {
            android.util.Log.e("ProtectionFragment", "Error starting CallMonitorService", e)
        }
    }

    private fun stopCallService() {
        try {
            val intent = Intent(requireContext(), com.phishguard.ai.service.CallMonitorService::class.java)
            requireContext().stopService(intent)
        } catch (e: Exception) {
            android.util.Log.e("ProtectionFragment", "Error stopping CallMonitorService", e)
        }
    }

    /**
     * Auto-detect installed messaging/social/browser apps
     * and display them in a dynamic RecyclerView section.
     */
    private fun setupDetectedApps(view: View) {
        val tvHeader = view.findViewById<TextView>(R.id.tvDetectedHeader)
        val tvDesc = view.findViewById<TextView>(R.id.tvDetectedDesc)
        val cardDetected = view.findViewById<CardView>(R.id.cardDetectedApps)
        val rvDetected = view.findViewById<RecyclerView>(R.id.rvDetectedApps)

        // Detect installed apps
        val detector = InstalledAppDetector(requireContext())
        val detectedApps = detector.detectApps()

        if (detectedApps.isNotEmpty()) {
            // Show section
            tvHeader.visibility = View.VISIBLE
            tvDesc.visibility = View.VISIBLE
            cardDetected.visibility = View.VISIBLE

            // Get currently enabled custom apps
            val enabledApps = prefs.getCustomMonitoredApps()

            // Setup RecyclerView
            rvDetected.layoutManager = LinearLayoutManager(requireContext())
            rvDetected.adapter = DetectedAppAdapter(detectedApps, enabledApps) { packageName, enabled ->
                prefs.setCustomMonitoredApp(packageName, enabled)
                // PhishGuardService will auto-update via preference listener
            }
        }
    }
}

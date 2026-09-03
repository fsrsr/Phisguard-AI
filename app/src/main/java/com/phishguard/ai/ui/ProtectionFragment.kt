package com.phishguard.ai.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.phishguard.ai.R
import com.phishguard.ai.core.InstalledAppDetector
import com.phishguard.ai.data.AppPreferences
import com.google.android.material.switchmaterial.SwitchMaterial

class ProtectionFragment : Fragment() {

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

    /** Toggle pemantauan aplikasi bawaan (chat & peramban). */
    private fun setupDefaultSwitches(view: View) {
        val switchWhatsapp = view.findViewById<SwitchMaterial>(R.id.switchWhatsapp)
        val switchTelegram = view.findViewById<SwitchMaterial>(R.id.switchTelegram)
        val switchFacebook = view.findViewById<SwitchMaterial>(R.id.switchFacebook)
        val switchInstagram = view.findViewById<SwitchMaterial>(R.id.switchInstagram)
        val switchChrome = view.findViewById<SwitchMaterial>(R.id.switchChrome)

        switchWhatsapp.isChecked = prefs.monitorWhatsApp
        switchTelegram.isChecked = prefs.monitorTelegram
        switchFacebook.isChecked = prefs.monitorFacebook
        switchInstagram.isChecked = prefs.monitorInstagram
        switchChrome.isChecked = prefs.monitorChrome

        switchWhatsapp.setOnCheckedChangeListener { _, checked -> prefs.monitorWhatsApp = checked }
        switchTelegram.setOnCheckedChangeListener { _, checked -> prefs.monitorTelegram = checked }
        switchFacebook.setOnCheckedChangeListener { _, checked -> prefs.monitorFacebook = checked }
        switchInstagram.setOnCheckedChangeListener { _, checked -> prefs.monitorInstagram = checked }
        switchChrome.setOnCheckedChangeListener { _, checked -> prefs.monitorChrome = checked }
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

        val detector = InstalledAppDetector(requireContext())
        val detectedApps = detector.detectApps()

        if (detectedApps.isNotEmpty()) {
            tvHeader.visibility = View.VISIBLE
            tvDesc.visibility = View.VISIBLE
            cardDetected.visibility = View.VISIBLE

            val enabledApps = prefs.getCustomMonitoredApps()
            rvDetected.layoutManager = LinearLayoutManager(requireContext())
            rvDetected.adapter = DetectedAppAdapter(detectedApps, enabledApps) { packageName, enabled ->
                prefs.setCustomMonitoredApp(packageName, enabled)
            }
        }
    }
}

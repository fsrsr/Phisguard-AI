package com.phishguard.ai

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.phishguard.ai.core.network.FirebaseSyncManager
import com.phishguard.ai.core.security.AppIntegrityChecker
import com.phishguard.ai.data.db.DatabaseSeeder
import com.phishguard.ai.ui.ActivityFragment
import com.phishguard.ai.ui.DashboardFragment
import com.phishguard.ai.ui.ProtectionFragment
import com.phishguard.ai.ui.SettingsFragment
import com.google.android.material.bottomnavigation.BottomNavigationView

class MainActivity : AppCompatActivity() {

    private companion object {
        const val REQ_PERMISSIONS = 1001
    }

    private val dashboardFragment = DashboardFragment()
    private val protectionFragment = ProtectionFragment()
    private val activityFragment = ActivityFragment()
    private val settingsFragment = SettingsFragment()

    private var activeFragment: Fragment = dashboardFragment

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // === APP INTEGRITY CHECK ===
        val checker = AppIntegrityChecker(this)
        val result = checker.performFullCheck()
        if (!result.isSecure()) {
            showTamperAlert(result)
            return
        }

        setContentView(R.layout.activity_main)

        // Seed database domain resmi bank Indonesia
        DatabaseSeeder.seedIfNeeded(this)

        requestRuntimePermissions()

        // 🔥 BULK UPLOAD EXCEL URL KE FIREBASE
        // Fungsi ini akan upload ribuan URL dari official_data.txt ke Firestore.
        // Uncomment baris di bawah ini sekali saja untuk mengupload, lalu comment lagi.
        // FirebaseSyncManager(this).bulkUploadOfficialUrlsFromAssets()

        // Add all fragments, hide all except dashboard
        supportFragmentManager.beginTransaction().apply {
            add(R.id.fragmentContainer, settingsFragment, "settings").hide(settingsFragment)
            add(R.id.fragmentContainer, activityFragment, "activity").hide(activityFragment)
            add(R.id.fragmentContainer, protectionFragment, "protection").hide(protectionFragment)
            add(R.id.fragmentContainer, dashboardFragment, "dashboard")
        }.commit()

        val bottomNav = findViewById<BottomNavigationView>(R.id.bottomNav)
        bottomNav.setOnItemSelectedListener { item ->
            val selectedFragment = when (item.itemId) {
                R.id.nav_dashboard -> dashboardFragment
                R.id.nav_protection -> protectionFragment
                R.id.nav_activity -> activityFragment
                R.id.nav_settings -> settingsFragment
                else -> dashboardFragment
            }

            if (selectedFragment != activeFragment) {
                supportFragmentManager.beginTransaction()
                    .hide(activeFragment)
                    .show(selectedFragment)
                    .commit()
                activeFragment = selectedFragment
            }
            true
        }
    }

    /**
     * Minta izin berbahaya yang dideklarasikan di manifest.
     *
     * Tanpa ini SmsReceiver tidak pernah menerima SMS, CallMonitorService
     * tidak bisa merekam, dan notifikasi peringatan tidak muncul di Android 13+
     * — izin di manifest saja tidak cukup sejak Android 6.
     */
    private fun requestRuntimePermissions() {
        val wanted = mutableListOf(
            Manifest.permission.RECEIVE_SMS,
            Manifest.permission.READ_SMS,
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.RECORD_AUDIO
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            wanted += Manifest.permission.POST_NOTIFICATIONS
        }

        val missing = wanted.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, missing.toTypedArray(), REQ_PERMISSIONS)
        }
    }

    /**
     * Show alert dialog when app integrity check fails.
     * App cannot proceed — user must reinstall.
     */
    private fun showTamperAlert(result: AppIntegrityChecker.IntegrityResult) {
        setContentView(R.layout.activity_main) // Need a basic layout for dialog
        AlertDialog.Builder(this)
            .setTitle(R.string.integrity_failed_title)
            .setMessage(R.string.integrity_failed_message)
            .setCancelable(false)
            .setPositiveButton("OK") { _, _ -> finish() }
            .show()
    }
}
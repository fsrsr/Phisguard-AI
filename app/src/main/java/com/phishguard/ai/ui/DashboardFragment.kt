package com.phishguard.ai.ui

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.phishguard.ai.R
import com.phishguard.ai.data.ActivityLogItem
import com.phishguard.ai.core.network.FirebaseSyncManager
import com.google.firebase.firestore.ListenerRegistration
import com.google.android.material.button.MaterialButton

class DashboardFragment : Fragment() {

    companion object {
        /** Jenis log yang dihitung sebagai "URL dipindai". */
        private val SCANNED_TYPES = setOf(
            ActivityLogItem.LogType.SAFE,
            ActivityLogItem.LogType.SUSPICIOUS,
            ActivityLogItem.LogType.PHISHING
        )

        /** Jenis log yang layak tampil di riwayat singkat dashboard. */
        private val NOTABLE_TYPES = setOf(
            ActivityLogItem.LogType.SUSPICIOUS,
            ActivityLogItem.LogType.PHISHING
        )
    }

    private lateinit var statusContainer: LinearLayout
    private lateinit var tvStatusTitle: TextView
    private lateinit var tvStatusDesc: TextView
    private lateinit var btnAction: MaterialButton
    private lateinit var tvStatScanned: TextView
    private lateinit var tvStatBlocked: TextView
    private lateinit var rvRecentThreats: RecyclerView
    private lateinit var tvNoThreats: TextView
    private lateinit var tvReportSummary: TextView

    private val recentAdapter = ActivityLogAdapter()
    private val recentItems = mutableListOf<ActivityLogItem>()
    private var reportListeners: List<ListenerRegistration> = emptyList()
    private var reportSync: FirebaseSyncManager? = null

    private var scannedCount = 0
    private var blockedCount = 0

    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.phishguard.ai.REPORT_UPDATE") {
                loadReports()
                return
            }
            if (intent?.action == "com.phishguard.ai.LOG_UPDATE") {
                val message = intent.getStringExtra("message") ?: return
                val source = intent.getStringExtra("source") ?: "System"
                val typeStr = intent.getStringExtra("type") ?: "SYSTEM"
                val type = try {
                    ActivityLogItem.LogType.valueOf(typeStr)
                } catch (e: Exception) {
                    ActivityLogItem.LogType.SYSTEM
                }

                // Update stats
                if (type in SCANNED_TYPES) {
                    scannedCount++
                    tvStatScanned.text = scannedCount.toString()
                }
                if (type == ActivityLogItem.LogType.PHISHING) {
                    blockedCount++
                    tvStatBlocked.text = blockedCount.toString()
                }

                // Riwayat singkat: ancaman, temuan mencurigakan, dan panggilan
                if (type in NOTABLE_TYPES) {
                    val item = ActivityLogItem(
                        message = message,
                        type = type,
                        sourceApp = source
                    )
                    recentItems.add(0, item)
                    if (recentItems.size > 5) recentItems.removeAt(recentItems.size - 1)
                    recentAdapter.updateItems(recentItems)
                    tvNoThreats.visibility = View.GONE
                    rvRecentThreats.visibility = View.VISIBLE
                }
            }
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        return inflater.inflate(R.layout.fragment_dashboard, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        statusContainer = view.findViewById(R.id.statusGradientContainer)
        tvStatusTitle = view.findViewById(R.id.tvStatusTitle)
        tvStatusDesc = view.findViewById(R.id.tvStatusDesc)
        btnAction = view.findViewById(R.id.btnAction)
        tvStatScanned = view.findViewById(R.id.tvStatScanned)
        tvStatBlocked = view.findViewById(R.id.tvStatBlocked)
        rvRecentThreats = view.findViewById(R.id.rvRecentThreats)
        tvNoThreats = view.findViewById(R.id.tvNoThreats)
        tvReportSummary = view.findViewById(R.id.tvReportSummary)

        rvRecentThreats.layoutManager = LinearLayoutManager(requireContext())
        rvRecentThreats.adapter = recentAdapter

        btnAction.setOnClickListener {
            val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            startActivity(intent)
        }
    }

    override fun onResume() {
        super.onResume()
        
        // Load persisted logs from SharedPreferences
        loadPersistedLogs()
        
        updateUI()
        loadReports()
        startReportSync()
        val filter = IntentFilter().apply {
            addAction("com.phishguard.ai.LOG_UPDATE")
            addAction("com.phishguard.ai.REPORT_UPDATE")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requireContext().registerReceiver(logReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            requireContext().registerReceiver(logReceiver, filter)
        }
    }

    override fun onPause() {
        super.onPause()
        try {
            requireContext().unregisterReceiver(logReceiver)
        } catch (_: Exception) {}
        reportListeners.forEach { it.remove() }
        reportListeners = emptyList()
    }

    private fun startReportSync() {
        reportListeners.forEach { it.remove() }
        val prefs = requireContext().getSharedPreferences("activity_log", Context.MODE_PRIVATE)
        val records = prefs.getStringSet("reports", emptySet()) ?: emptySet()
        if (records.isEmpty()) return
        reportSync = FirebaseSyncManager(requireContext().applicationContext)
        reportListeners = reportSync!!.listenToReports(records) { reportId, status, feedback ->
            updateLocalReport(reportId, status, feedback)
        }
    }

    private fun statusRank(status: String): Int = when (status.lowercase()) {
        "terkirim", "pending" -> 1
        "diproses", "processing" -> 2
        "selesai", "done", "completed" -> 3
        "ditolak", "rejected" -> 3
        else -> 0
    }

    private fun updateLocalReport(reportId: String, status: String, feedback: String) {
        val prefs = requireContext().getSharedPreferences("activity_log", Context.MODE_PRIVATE)
        val reports = (prefs.getStringSet("reports", emptySet()) ?: emptySet()).map { record ->
            if (record.startsWith("$reportId|")) {
                val parts = record.split("|", limit = 5)
                val current = parts.getOrNull(3).orEmpty()
                if (statusRank(status) >= statusRank(current)) {
                    parts.take(3).joinToString("|") + "|$status|${feedback.replace('|', ' ').take(200)}"
                } else record
            } else record
        }.toSet()
        prefs.edit().putStringSet("reports", reports).apply()
        loadReports()
    }

    private fun updateUI() {
        if (isServiceEnabled()) {
            statusContainer.setBackgroundResource(R.drawable.bg_status_active)
            tvStatusTitle.text = getString(R.string.status_active)
            tvStatusDesc.text = getString(R.string.status_desc_active)
            btnAction.text = getString(R.string.btn_manage)
        } else {
            statusContainer.setBackgroundResource(R.drawable.bg_status_inactive)
            tvStatusTitle.text = getString(R.string.status_inactive)
            tvStatusDesc.text = getString(R.string.status_desc_inactive)
            btnAction.text = getString(R.string.btn_enable)
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
    
    private fun loadPersistedLogs() {
        val prefs = requireContext().getSharedPreferences("activity_log", Context.MODE_PRIVATE)
        val logs = prefs.getStringSet("logs", emptySet()) ?: emptySet()
        
        // Parse log entries: timestamp|message|source|type
        val parsedLogs = logs.mapNotNull { entry ->
            val parts = entry.split("|")
            if (parts.size >= 4) {
                try {
                    ActivityLogItem(
                        timestamp = parts[0].toLong(),
                        message = parts[1],
                        sourceApp = parts[2],
                        type = ActivityLogItem.LogType.valueOf(parts[3])
                    )
                } catch (e: Exception) {
                    null
                }
            } else {
                null
            }
        }.sortedByDescending { it.timestamp }
        
        // Read stats from separate counters (not from logs)
        scannedCount = prefs.getInt("scanned_count", 0)
        blockedCount = prefs.getInt("blocked_count", 0)
        
        tvStatScanned.text = scannedCount.toString()
        tvStatBlocked.text = blockedCount.toString()
        
        // Riwayat singkat: 5 kejadian penting terakhir
        recentItems.clear()
        recentItems.addAll(parsedLogs.filter { it.type in NOTABLE_TYPES }.take(5))
        
        recentAdapter.updateItems(recentItems)
        
        if (recentItems.isEmpty()) {
            tvNoThreats.visibility = View.VISIBLE
            rvRecentThreats.visibility = View.GONE
        } else {
            tvNoThreats.visibility = View.GONE
            rvRecentThreats.visibility = View.VISIBLE
        }
    }

    private fun loadReports() {
        val reports = requireContext().getSharedPreferences("activity_log", Context.MODE_PRIVATE)
            .getStringSet("reports", emptySet()) ?: emptySet()
        val latest = reports.maxByOrNull { it.split('|').getOrNull(1)?.toLongOrNull() ?: 0L }
        tvReportSummary.text = if (latest == null) {
            getString(R.string.no_reports)
        } else {
            val parts = latest.split("|", limit = 5)
            val feedback = parts.getOrNull(4).orEmpty().takeIf { it.isNotBlank() }?.let { " • Feedback: $it" }.orEmpty()
            getString(R.string.reports_summary, reports.size, parts.getOrNull(2).orEmpty(), parts.getOrNull(3).orEmpty(), feedback)
        }
    }
}

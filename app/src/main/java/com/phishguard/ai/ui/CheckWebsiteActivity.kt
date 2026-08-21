package com.phishguard.ai.ui

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.phishguard.ai.R
import com.phishguard.ai.core.recon.WebsiteReconAgent

/**
 * Entry point when user shares a URL to PhishGuard via Android Share Sheet.
 *
 * Flow:
 *   1. Receive shared URL via Intent.ACTION_SEND
 *   2. Show loading spinner
 *   3. Run WebsiteReconAgent analysis
 *   4. Open ReconResultActivity with results
 *   5. Finish self
 */
class CheckWebsiteActivity : AppCompatActivity() {

    private val TAG = "CheckWebsiteActivity"
    private val agent = WebsiteReconAgent()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_recon_loading)

        val url = extractUrlFromIntent(intent)
        if (url.isNullOrBlank()) {
            showError("Tidak ada URL yang diterima.")
            return
        }

        val tvUrl = findViewById<TextView>(R.id.tvReconUrl)
        val tvStatus = findViewById<TextView>(R.id.tvReconStatus)
        tvUrl.text = url
        tvStatus.text = getString(R.string.recon_analyzing)

        runRecon(url)
    }

    private fun runRecon(url: String) {
        agent.analyze(url) { result ->
            runOnUiThread {
                val intent = Intent(this, ReconResultActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    putExtra(ReconResultActivity.EXTRA_RECON_URL, result.url)
                    putExtra(ReconResultActivity.EXTRA_RECON_DOMAIN, result.domain)
                    putExtra(ReconResultActivity.EXTRA_RECON_RISK, result.overallRisk.name)
                    putExtra(ReconResultActivity.EXTRA_RECON_CONFIDENCE, result.confidence)
                    putExtra(ReconResultActivity.EXTRA_RECON_SUMMARY, result.summary)
                    // Serialize findings as JSON
                    putExtra(ReconResultActivity.EXTRA_RECON_FINDINGS,
                        com.google.gson.Gson().toJson(result.findings))
                    putExtra(ReconResultActivity.EXTRA_RECON_SE_INDICATORS,
                        com.google.gson.Gson().toJson(result.socialEngineeringIndicators))
                }
                startActivity(intent)
                finish()
            }
        }
    }

    private fun extractUrlFromIntent(intent: Intent): String? {
        // From ACTION_SEND
        if (intent.action == Intent.ACTION_SEND && intent.type == "text/plain") {
            return intent.getStringExtra(Intent.EXTRA_TEXT)?.trim()
        }
        // From direct launch with URL extra
        return intent.getStringExtra("url")?.trim()
    }

    private fun showError(message: String) {
        val tvStatus = findViewById<TextView>(R.id.tvReconStatus)
        tvStatus?.text = message
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({ finish() }, 2500)
    }

    override fun onDestroy() {
        super.onDestroy()
    }
}

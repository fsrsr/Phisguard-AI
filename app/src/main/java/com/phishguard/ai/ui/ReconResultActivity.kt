package com.phishguard.ai.ui

import android.os.Bundle
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.phishguard.ai.R
import com.phishguard.ai.core.recon.WebsiteReconAgent

/**
 * Popup hasil recon — tampilan mirip WarningActivity v1.0.
 *
 * Menampilkan:
 * - Risk level badge (SAFE / LOW / MEDIUM / HIGH / CRITICAL)
 * - Confidence meter
 * - Ringkasan AI recon
 * - Daftar findings per kategori
 * - Social engineering indicators (jika ada)
 */
class ReconResultActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_RECON_URL = "recon_url"
        const val EXTRA_RECON_DOMAIN = "recon_domain"
        const val EXTRA_RECON_RISK = "recon_risk"
        const val EXTRA_RECON_CONFIDENCE = "recon_confidence"
        const val EXTRA_RECON_SUMMARY = "recon_summary"
        const val EXTRA_RECON_FINDINGS = "recon_findings"
        const val EXTRA_RECON_SE_INDICATORS = "recon_se_indicators"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_recon_result)

        val url = intent.getStringExtra(EXTRA_RECON_URL) ?: ""
        val domain = intent.getStringExtra(EXTRA_RECON_DOMAIN) ?: ""
        val riskName = intent.getStringExtra(EXTRA_RECON_RISK) ?: "MEDIUM"
        val confidence = intent.getFloatExtra(EXTRA_RECON_CONFIDENCE, 0.5f)
        val summary = intent.getStringExtra(EXTRA_RECON_SUMMARY) ?: ""
        val findingsJson = intent.getStringExtra(EXTRA_RECON_FINDINGS) ?: "[]"
        val seJson = intent.getStringExtra(EXTRA_RECON_SE_INDICATORS) ?: "[]"

        val risk = try {
            WebsiteReconAgent.RiskLevel.valueOf(riskName)
        } catch (_: Exception) {
            WebsiteReconAgent.RiskLevel.MEDIUM
        }

        val findings: List<WebsiteReconAgent.Finding> = try {
            val type = object : TypeToken<List<WebsiteReconAgent.Finding>>() {}.type
            Gson().fromJson(findingsJson, type)
        } catch (_: Exception) {
            emptyList()
        }

        val seIndicators: List<String> = try {
            val type = object : TypeToken<List<String>>() {}.type
            Gson().fromJson(seJson, type)
        } catch (_: Exception) {
            emptyList()
        }

        // ── Bind UI ───────────────────────────────────────────────────
        val ivIcon = findViewById<ImageView>(R.id.ivReconIcon)
        val tvBadge = findViewById<TextView>(R.id.tvReconBadge)
        val tvTitle = findViewById<TextView>(R.id.tvReconTitle)
        val tvDomain = findViewById<TextView>(R.id.tvReconDomain)
        val tvSummary = findViewById<TextView>(R.id.tvReconSummary)
        val pbConfidence = findViewById<ProgressBar>(R.id.pbReconConfidence)
        val tvConfidence = findViewById<TextView>(R.id.tvReconConfidence)
        val tvUrl = findViewById<TextView>(R.id.tvReconUrl)
        val containerFindings = findViewById<LinearLayout>(R.id.containerFindings)
        val containerSe = findViewById<LinearLayout>(R.id.containerSeIndicators)
        val tvSeTitle = findViewById<TextView>(R.id.tvSeTitle)
        val btnClose = findViewById<MaterialButton>(R.id.btnReconClose)

        // ── Colors based on risk ───────────────────────────────────────
        val (accent, accentDark, accentLight) = when (risk) {
            WebsiteReconAgent.RiskLevel.CRITICAL -> Triple(
                ContextCompat.getColor(this, R.color.error),
                ContextCompat.getColor(this, R.color.error_dark),
                ContextCompat.getColor(this, R.color.error_light)
            )
            WebsiteReconAgent.RiskLevel.HIGH -> Triple(
                ContextCompat.getColor(this, R.color.error),
                ContextCompat.getColor(this, R.color.error_dark),
                ContextCompat.getColor(this, R.color.error_light)
            )
            WebsiteReconAgent.RiskLevel.MEDIUM -> Triple(
                ContextCompat.getColor(this, R.color.warning),
                ContextCompat.getColor(this, R.color.warning_dark),
                ContextCompat.getColor(this, R.color.warning_light)
            )
            WebsiteReconAgent.RiskLevel.LOW -> Triple(
                ContextCompat.getColor(this, R.color.primary),
                ContextCompat.getColor(this, R.color.primary_dark),
                ContextCompat.getColor(this, R.color.primary_light)
            )
            WebsiteReconAgent.RiskLevel.SAFE -> Triple(
                ContextCompat.getColor(this, R.color.success),
                ContextCompat.getColor(this, R.color.success_dark),
                ContextCompat.getColor(this, R.color.success_light)
            )
        }

        // Apply accent
        ivIcon.setColorFilter(accent)
        findViewById<android.view.View>(R.id.iconReconContainer).background
            ?.mutate()?.setTint(accentLight)
        tvBadge.background?.mutate()?.setTint(accentLight)
        tvBadge.setTextColor(accentDark)
        tvDomain.setTextColor(accentDark)
        pbConfidence.progressTintList = android.content.res.ColorStateList.valueOf(accent)
        btnClose.backgroundTintList = android.content.res.ColorStateList.valueOf(accent)

        // Badge text
        val badgeText = when (risk) {
            WebsiteReconAgent.RiskLevel.CRITICAL -> "SANGAT BERBAHAYA"
            WebsiteReconAgent.RiskLevel.HIGH -> "BERBAHAYA"
            WebsiteReconAgent.RiskLevel.MEDIUM -> "PERLU DIPERIKSA"
            WebsiteReconAgent.RiskLevel.LOW -> "RENDAH RISIKO"
            WebsiteReconAgent.RiskLevel.SAFE -> "AMAN"
        }
        tvBadge.text = badgeText

        // Confidence meter
        val percent = (confidence.coerceIn(0f, 1f) * 100).toInt()
        pbConfidence.progress = percent
        tvConfidence.text = "$percent%"

        // Title + domain
        tvTitle.text = when (risk) {
            WebsiteReconAgent.RiskLevel.CRITICAL,
            WebsiteReconAgent.RiskLevel.HIGH -> getString(R.string.recon_title_dangerous)
            WebsiteReconAgent.RiskLevel.MEDIUM -> getString(R.string.recon_title_suspicious)
            WebsiteReconAgent.RiskLevel.LOW -> getString(R.string.recon_title_low_risk)
            WebsiteReconAgent.RiskLevel.SAFE -> getString(R.string.recon_title_safe)
        }
        tvDomain.text = domain
        tvSummary.text = summary
        tvUrl.text = url

        // ── Render findings ────────────────────────────────────────────
        containerFindings.removeAllViews()
        for (finding in findings) {
            val itemView = layoutInflater.inflate(R.layout.item_recon_finding, containerFindings, false)
            val tvCat = itemView.findViewById<TextView>(R.id.tvFindingCategory)
            val tvDetail = itemView.findViewById<TextView>(R.id.tvFindingDetail)
            val indicator = itemView.findViewById<android.view.View>(R.id.viewRiskIndicator)

            tvCat.text = finding.category
            tvDetail.text = finding.detail

            val findingColor = when (finding.risk) {
                WebsiteReconAgent.RiskLevel.CRITICAL,
                WebsiteReconAgent.RiskLevel.HIGH -> ContextCompat.getColor(this, R.color.error)
                WebsiteReconAgent.RiskLevel.MEDIUM -> ContextCompat.getColor(this, R.color.warning)
                WebsiteReconAgent.RiskLevel.LOW -> ContextCompat.getColor(this, R.color.primary)
                WebsiteReconAgent.RiskLevel.SAFE -> ContextCompat.getColor(this, R.color.success)
            }
            indicator.setBackgroundColor(findingColor)
            containerFindings.addView(itemView)
        }

        // ── Render social engineering indicators ───────────────────────
        if (seIndicators.isNotEmpty()) {
            tvSeTitle.visibility = android.view.View.VISIBLE
            containerSe.visibility = android.view.View.VISIBLE
            containerSe.removeAllViews()
            for (indicator in seIndicators) {
                val tv = TextView(this).apply {
                    text = "⚠ $indicator"
                    textSize = 13f
                    setTextColor(ContextCompat.getColor(context, R.color.warning_dark))
                    setPadding(0, 4.dpToPx(), 0, 4.dpToPx())
                }
                containerSe.addView(tv)
            }
        } else {
            tvSeTitle.visibility = android.view.View.GONE
            containerSe.visibility = android.view.View.GONE
        }

        // Close button
        btnClose.setOnClickListener { finish() }
    }

    private fun Int.dpToPx(): Int =
        (this * resources.displayMetrics.density).toInt()
}

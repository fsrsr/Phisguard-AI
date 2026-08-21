package com.phishguard.ai.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.phishguard.ai.R
import com.phishguard.ai.core.InstalledAppDetector
import com.google.android.material.switchmaterial.SwitchMaterial

/**
 * RecyclerView Adapter untuk menampilkan detected apps di ProtectionFragment.
 *
 * Menampilkan icon asli dari HP, nama app, kategori, dan toggle switch.
 */
class DetectedAppAdapter(
    private val apps: List<InstalledAppDetector.DetectedApp>,
    private val enabledApps: Set<String>,
    private val onToggle: (packageName: String, enabled: Boolean) -> Unit
) : RecyclerView.Adapter<DetectedAppAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val icon: ImageView = view.findViewById(R.id.imgDetectedAppIcon)
        val name: TextView = view.findViewById(R.id.tvDetectedAppName)
        val category: TextView = view.findViewById(R.id.tvDetectedAppCategory)
        val toggle: SwitchMaterial = view.findViewById(R.id.switchDetectedApp)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_detected_app, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val app = apps[position]

        holder.icon.setImageDrawable(app.icon)
        holder.name.text = app.appName
        holder.category.text = app.category

        // Set checked state without triggering listener
        holder.toggle.setOnCheckedChangeListener(null)
        holder.toggle.isChecked = enabledApps.contains(app.packageName)

        holder.toggle.setOnCheckedChangeListener { _, isChecked ->
            onToggle(app.packageName, isChecked)
        }
    }

    override fun getItemCount(): Int = apps.size
}

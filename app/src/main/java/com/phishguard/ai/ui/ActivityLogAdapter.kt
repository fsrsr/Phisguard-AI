package com.phishguard.ai.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.phishguard.ai.R
import com.phishguard.ai.data.ActivityLogItem
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ActivityLogAdapter(
    private val items: MutableList<ActivityLogItem> = mutableListOf()
) : RecyclerView.Adapter<ActivityLogAdapter.ViewHolder>() {

    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val ivIcon: ImageView = view.findViewById(R.id.ivLogIcon)
        val tvMessage: TextView = view.findViewById(R.id.tvLogMessage)
        val tvSource: TextView = view.findViewById(R.id.tvLogSource)
        val tvTime: TextView = view.findViewById(R.id.tvLogTime)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_activity_log, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.tvMessage.text = item.message
        holder.tvSource.text = item.sourceApp
        holder.tvTime.text = timeFormat.format(Date(item.timestamp))

        val context = holder.itemView.context
        when (item.type) {
            ActivityLogItem.LogType.SAFE -> {
                holder.ivIcon.setImageResource(R.drawable.ic_protection)
                holder.ivIcon.setColorFilter(context.getColor(R.color.success))
            }
            ActivityLogItem.LogType.SUSPICIOUS -> {
                holder.ivIcon.setImageResource(android.R.drawable.ic_dialog_alert)
                holder.ivIcon.setColorFilter(context.getColor(R.color.warning))
            }
            ActivityLogItem.LogType.PHISHING -> {
                holder.ivIcon.setImageResource(android.R.drawable.ic_dialog_alert)
                holder.ivIcon.setColorFilter(context.getColor(R.color.error))
            }
            ActivityLogItem.LogType.CALL -> {
                holder.ivIcon.setImageResource(android.R.drawable.ic_menu_call)
                holder.ivIcon.setColorFilter(context.getColor(R.color.warning))
            }
            ActivityLogItem.LogType.SYSTEM -> {
                holder.ivIcon.setImageResource(android.R.drawable.ic_dialog_info)
                holder.ivIcon.setColorFilter(context.getColor(R.color.primary))
            }
        }
    }

    override fun getItemCount() = items.size

    fun addItem(item: ActivityLogItem) {
        items.add(0, item)
        notifyItemInserted(0)
    }

    fun setFilter(type: ActivityLogItem.LogType?) {
        // This is handled by the fragment — it passes a filtered list
    }

    fun updateItems(newItems: List<ActivityLogItem>) {
        items.clear()
        items.addAll(newItems)
        notifyDataSetChanged()
    }
}

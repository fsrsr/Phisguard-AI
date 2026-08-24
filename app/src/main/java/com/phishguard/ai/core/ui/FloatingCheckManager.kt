package com.phishguard.ai.core.ui

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.os.Build
import android.provider.Settings
import android.util.Log
import android.view.Gravity
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.FrameLayout
import android.widget.TextView
import androidx.cardview.widget.CardView
import com.phishguard.ai.R
import com.phishguard.ai.ui.CheckWebsiteActivity

/**
 * Manages a floating overlay button "Check this website" yang muncul
 * saat user berada di browser. Ketika diklik, menjalankan AI recon
 * pada URL yang sedang dikunjungi.
 *
 * Dipanggil dari PhishGuardService — tidak mengubah logic v1.0.
 * Redesigned: circular, draggable anywhere (X+Y), aesthetic with animations.
 */
class FloatingCheckManager(private val context: Context) {

    private val TAG = "FloatingCheckManager"
    private var windowManager: WindowManager? = null
    private var floatingView: View? = null
    private var isShowing = false
    private var currentUrl: String = ""

    private val prefs by lazy {
        context.getSharedPreferences("floating_check", Context.MODE_PRIVATE)
    }

    /** Toggle aktivasi dari Settings/Protection. */
    var isEnabled: Boolean
        get() = prefs.getBoolean("enabled", true)
        set(value) = prefs.edit().putBoolean("enabled", value).apply()

    /** Saved position for persistence across sessions. */
    private var savedX: Int
        get() = prefs.getInt("pos_x", 0)
        set(value) = prefs.edit().putInt("pos_x", value).apply()

    private var savedY: Int
        get() = prefs.getInt("pos_y", 0)
        set(value) = prefs.edit().putInt("pos_y", value).apply()

    /** Whether label is expanded. */
    private var isLabelExpanded = false

    /**
     * Tampilkan tombol floating dengan URL yang sedang aktif.
     * Panggil setiap kali PhishGuardService mendeteksi URL browser baru.
     */
    @SuppressLint("ClickableViewAccessibility")
    fun show(url: String) {
        if (!isEnabled) {
            Log.d(TAG, "Floating check disabled")
            return
        }
        if (!Settings.canDrawOverlays(context)) {
            Log.w(TAG, "Overlay permission belum diberikan — silakan izinkan di Settings → Apps → PhishGuard → Display over other apps")
            return
        }
        currentUrl = url

        // Update URL saja jika sudah tampil dan view masih valid
        if (isShowing && floatingView != null) {
            Log.d(TAG, "Update URL: $url")
            return
        }

        // Reset stale state
        if (isShowing && floatingView == null) {
            isShowing = false
        }

        try {
            windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager

            // Inflate custom layout
            val inflater = LayoutInflater.from(context)
            floatingView = inflater.inflate(R.layout.layout_floating_check, null)

            val rootView = floatingView!!.findViewById<View>(R.id.flFloatingRoot)
            val cardBtn = floatingView!!.findViewById<CardView>(R.id.cvFloatingBtn)
            val labelTv = floatingView!!.findViewById<TextView>(R.id.tvFloatingLabel)
            val dragHandle = floatingView!!.findViewById<View>(R.id.vDragHandle)

            // Restore saved position
            val params = WindowManager.LayoutParams(
                WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                else
                    WindowManager.LayoutParams.TYPE_PHONE,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                        WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                        WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.TRANSLUCENT
            ).apply {
                gravity = Gravity.START or Gravity.TOP
                x = if (savedX != 0) savedX else 16
                y = if (savedY != 0) savedY else (getScreenHeight() / 2)
            }

            // Entrance animation
            cardBtn.alpha = 0f
            cardBtn.scaleX = 0.5f
            cardBtn.scaleY = 0.5f
            cardBtn.animate()
                .alpha(1f)
                .scaleX(1f)
                .scaleY(1f)
                .setDuration(300)
                .setInterpolator(AccelerateDecelerateInterpolator())
                .start()

            // Touch handling — free drag X+Y + click
            var initialX = 0f
            var initialY = 0f
            var initialTouchX = 0f
            var initialTouchY = 0f
            var isDragging = false
            var dragStarted = false

            val onTouchListener = View.OnTouchListener { _, event ->
                when (event.action) {
                    MotionEvent.ACTION_DOWN -> {
                        initialX = params.x.toFloat()
                        initialY = params.y.toFloat()
                        initialTouchX = event.rawX
                        initialTouchY = event.rawY
                        isDragging = false
                        dragStarted = false

                        // Scale down slightly on press
                        cardBtn.animate().scaleX(0.95f).scaleY(0.95f).setDuration(100).start()
                        true
                    }
                    MotionEvent.ACTION_MOVE -> {
                        val dx = event.rawX - initialTouchX
                        val dy = event.rawY - initialTouchY

                        if (!dragStarted && (Math.abs(dx) > 8 || Math.abs(dy) > 8)) {
                            dragStarted = true
                            isDragging = true
                            // Show label on drag start
                            if (!isLabelExpanded) {
                                expandLabel(labelTv)
                            }
                        }

                        if (isDragging) {
                            params.x = (initialX + dx).toInt()
                            params.y = (initialY + dy).toInt()
                            // Clamp to screen bounds
                            params.x = params.x.coerceIn(0, getScreenWidth() - cardBtn.width)
                            params.y = params.y.coerceIn(0, getScreenHeight() - cardBtn.height)
                            windowManager?.updateViewLayout(floatingView, params)
                        }
                        true
                    }
                    MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                        // Restore scale
                        cardBtn.animate().scaleX(1f).scaleY(1f).setDuration(150).start()

                        if (!isDragging) {
                            // Tap/click — launch recon
                            onCheckClicked()
                        } else {
                            // Save position after drag
                            savedX = params.x
                            savedY = params.y
                            // Hide label after drag ends
                            collapseLabel(labelTv)
                        }
                        true
                    }
                    else -> false
                }
            }

            cardBtn.setOnTouchListener(onTouchListener)
            dragHandle.setOnTouchListener(onTouchListener)

            // Long press to expand/collapse label
            cardBtn.setOnLongClickListener {
                if (!isLabelExpanded) {
                    expandLabel(labelTv)
                } else {
                    collapseLabel(labelTv)
                }
                true
            }

            windowManager?.addView(floatingView, params)
            isShowing = true
            Log.d(TAG, "Floating button ditampilkan untuk: $url")

        } catch (e: Exception) {
            Log.e(TAG, "Gagal menampilkan floating button", e)
        }
    }

    /** Expand label with animation. */
    private fun expandLabel(labelTv: TextView) {
        if (isLabelExpanded) return
        isLabelExpanded = true
        labelTv.visibility = View.VISIBLE
        labelTv.alpha = 0f
        labelTv.translationX = 40f
        labelTv.animate()
            .alpha(1f)
            .translationX(0f)
            .setDuration(200)
            .setInterpolator(AccelerateDecelerateInterpolator())
            .start()
    }

    /** Collapse label with animation. */
    private fun collapseLabel(labelTv: TextView) {
        if (!isLabelExpanded) return
        isLabelExpanded = false
        labelTv.animate()
            .alpha(0f)
            .translationX(40f)
            .setDuration(150)
            .withEndAction { labelTv.visibility = View.GONE }
            .start()
    }

    /** Sembunyikan tombol floating. */
    fun hide() {
        if (!isShowing || floatingView == null) return
        try {
            val cardBtn = floatingView!!.findViewById<CardView>(R.id.cvFloatingBtn)
            // Exit animation
            cardBtn.animate()
                .alpha(0f)
                .scaleX(0.5f)
                .scaleY(0.5f)
                .setDuration(200)
                .withEndAction {
                    windowManager?.removeView(floatingView)
                    floatingView = null
                    isShowing = false
                    Log.d(TAG, "Floating button disembunyikan")
                }
                .start()
        } catch (e: Exception) {
            Log.e(TAG, "Gagal menyembunyikan floating button", e)
        }
    }

    /** Update URL tanpa show/hide. */
    fun updateUrl(url: String) {
        currentUrl = url
    }

    /** Baca URL yang tersimpan saat ini (untuk cek apakah sudah ada sebelum re-show). */
    fun currentUrlOrEmpty(): String = currentUrl

    /** Cleanup — panggil saat service destroy. */
    fun destroy() {
        if (isShowing && floatingView != null) {
            try {
                windowManager?.removeView(floatingView)
            } catch (_: Exception) {}
        }
        floatingView = null
        isShowing = false
    }

    private fun onCheckClicked() {
        if (currentUrl.isBlank()) {
            Log.w(TAG, "Tidak ada URL untuk dianalisis")
            return
        }
        Log.d(TAG, "Check clicked: $currentUrl")

        // Launch CheckWebsiteActivity dengan URL langsung
        try {
            val intent = Intent(context, CheckWebsiteActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                putExtra("url", currentUrl)
            }
            context.startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Gagal launch CheckWebsiteActivity", e)
        }
    }

    private fun getScreenWidth(): Int = context.resources.displayMetrics.widthPixels
    private fun getScreenHeight(): Int = context.resources.displayMetrics.heightPixels
}

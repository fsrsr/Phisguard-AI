package com.phishguard.ai.core.ui

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.graphics.drawable.Drawable
import android.os.Build
import android.provider.Settings
import android.util.Log
import android.view.Gravity
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.ImageView
import com.phishguard.ai.R
import com.phishguard.ai.ui.CheckWebsiteActivity

/**
 * Manages a floating overlay button "Check this website" yang muncul
 * saat user berada di browser. Ketika diklik, menjalankan AI recon
 * pada URL yang sedang dikunjungi.
 *
 * Dipanggil dari PhishGuardService — tidak mengubah logic v1.0.
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

    /**
     * Tampilkan tombol floating dengan URL yang sedang aktif.
     * Panggil setiap kali PhishGuardService mendeteksi URL browser baru.
     */
    @SuppressLint("ClickableViewAccessibility")
    fun show(url: String) {
        if (!isEnabled) return
        if (!Settings.canDrawOverlays(context)) {
            Log.w(TAG, "Overlay permission belum diberikan")
            return
        }
        currentUrl = url

        // Update URL saja jika sudah tampil
        if (isShowing && floatingView != null) {
            Log.d(TAG, "Update URL: $url")
            return
        }

        try {
            windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager

            // Inflate custom layout
            val inflater = LayoutInflater.from(context)
            floatingView = inflater.inflate(R.layout.layout_floating_check, null)

            val btnCheck = floatingView!! // Root LinearLayout IS the button

            // Layout params — posisi kanan bawah
            val params = WindowManager.LayoutParams(
                WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
                else
                    WindowManager.LayoutParams.TYPE_PHONE,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                        WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
                PixelFormat.TRANSLUCENT
            ).apply {
                gravity = Gravity.END or Gravity.CENTER_VERTICAL
                x = 16
            }

            // Drag to reposition
            var initialX = 0
            var initialY = 0
            var initialTouchX = 0f
            var initialTouchY = 0f
            var isDragging = false

            btnCheck.setOnTouchListener { _, event ->
                when (event.action) {
                    MotionEvent.ACTION_DOWN -> {
                        initialX = params.x
                        initialY = params.y
                        initialTouchX = event.rawX
                        initialTouchY = event.rawY
                        isDragging = false
                        true
                    }
                    MotionEvent.ACTION_MOVE -> {
                        val dx = event.rawX - initialTouchX
                        val dy = event.rawY - initialTouchY
                        if (Math.abs(dx) > 10 || Math.abs(dy) > 10) {
                            isDragging = true
                            params.x = initialX - dx.toInt()
                            windowManager?.updateViewLayout(floatingView, params)
                        }
                        true
                    }
                    MotionEvent.ACTION_UP -> {
                        if (!isDragging) {
                            onCheckClicked()
                        }
                        true
                    }
                    else -> false
                }
            }

            windowManager?.addView(floatingView, params)
            isShowing = true
            Log.d(TAG, "Floating button ditampilkan untuk: $url")

        } catch (e: Exception) {
            Log.e(TAG, "Gagal menampilkan floating button", e)
        }
    }

    /** Sembunyikan tombol floating. */
    fun hide() {
        if (!isShowing || floatingView == null) return
        try {
            windowManager?.removeView(floatingView)
            floatingView = null
            isShowing = false
            Log.d(TAG, "Floating button disembunyikan")
        } catch (e: Exception) {
            Log.e(TAG, "Gagal menyembunyikan floating button", e)
        }
    }

    /** Update URL tanpa show/hide. */
    fun updateUrl(url: String) {
        currentUrl = url
    }

    /** Cleanup — panggil saat service destroy. */
    fun destroy() {
        hide()
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
}

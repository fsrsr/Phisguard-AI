package com.phishguard.ai

import android.accessibilityservice.AccessibilityService
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.phishguard.ai.core.ai.AnalysisPipeline
import com.phishguard.ai.core.ai.AnalysisResult
import com.phishguard.ai.core.ai.LayeredResult
import com.phishguard.ai.core.ai.ThreatLayer
import com.phishguard.ai.core.ai.UrlRiskScorer
import com.phishguard.ai.core.ui.FloatingCheckManager
import com.phishguard.ai.data.db.PhishingNumber
import com.phishguard.ai.core.network.FirebaseSyncManager
import com.phishguard.ai.core.network.ServerSyncManager
import com.phishguard.ai.data.AppPreferences
import com.phishguard.ai.data.db.DatabaseSeeder
import com.phishguard.ai.data.db.PhishingDatabase
import com.phishguard.ai.data.db.PhishingUrl
import com.phishguard.ai.ui.WarningActivity

class PhishGuardService : AccessibilityService() {

    private val TAG = "PhishGuardService"
    private var pipeline: AnalysisPipeline? = null
    private var prefs: AppPreferences? = null
    private var isReady = false
    private var floatingCheck: FloatingCheckManager? = null

    // Track last URL to avoid duplicate scans
    private var lastDetectedUrl: String = ""
    private var lastDetectedMessage: String = ""
    // Pesan yang user pilih "Abaikan". Tahan sampai isi pesan berubah agar
    // window-state event setelah WarningActivity ditutup tidak memunculkan
    // warning yang sama lagi.
    private var ignoredMessage: String = ""
    private var warningShownForUrl: String = ""


    // Pemindaian ulang isi halaman. Analisis pertama berjalan pada
    // milidetik yang sama dengan perubahan bilah alamat, saat halaman belum
    // dirender sama sekali — terukur hanya 33 karakter teks tertangkap pada
    // situs judol nyata. Sinyal berbasis konten karena itu tidak pernah
    // punya bahan. Pemindaian kedua dijadwalkan setelah halaman sempat
    // tampil.
    private val rescanHandler = Handler(Looper.getMainLooper())
    private var pendingRescan: Runnable? = null

    // Mute-window setelah blokir+back: cegah loop scan bila browser reload
    // halaman phising yang sama (fenomena "sudah klik blokir tetapi tidak ke back").
    private var backMuteUntil = 0L

    // HITL: URL yang ditandai AMAN oleh pengguna → persisten. Dulu hanya
    // bertahan satu sesi, sehingga keputusan "Aman" pengguna hilang setelah
    // service restart dan situs yang sama diperingatkan lagi (false positive
    // yang terasa paling menjengkelkan).
    private val hitlWhitelistUrls = mutableSetOf<String>()

    // HITL: URL yang ditandai PHISHING oleh pengguna → persisten via SharedPreferences
    private val hitlBlacklistUrls = mutableSetOf<String>()

    // Back-after-block yang deterministik: flag + broadcast onDestroy dari
    // WarningActivity (bukan Handler timer 600ms yang balapan dengan animasi
    // penutupan activity dan sering menutup warning itu sendiri).
    private var backPendingAfterWarning = false

    // BroadcastReceiver untuk keputusan HITL dari WarningActivity
    private val hitlReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == ACTION_BLOCK_NUMBER) {
                val number = intent.getStringExtra("phone_number").orEmpty()
                if (number.isNotBlank()) blockPhoneNumber(number)
                return
            }

            if (intent?.action == ACTION_IGNORE_MESSAGE) {
                ignoredMessage = intent.getStringExtra("ignored_message").orEmpty()
                lastDetectedMessage = ignoredMessage
                Log.d(TAG, "HITL ✅ User mengabaikan pesan: ${ignoredMessage.take(80)}")
                return
            }

            if (intent?.action == ACTION_REPORT_MESSAGE) {
                ignoredMessage = intent.getStringExtra("ignored_message").orEmpty()
                lastDetectedMessage = ignoredMessage
                backPendingAfterWarning = false
                val reportedUrl = intent.getStringExtra("target_url").orEmpty()
                if (reportedUrl.isNotBlank()) {
                    val normalized = normalizeUrl(reportedUrl)
                    hitlBlacklistUrls.add(normalized)
                    saveUrlSet(PREF_BLACKLIST, hitlBlacklistUrls)
                    saveToRoomBlacklist(normalized)
                    Log.d(TAG, "HITL 🚩 Pesan dilaporkan: $normalized")
                }
                return
            }

            // ACTION_WARNING_CLOSED TIDAK membawa target_url — tangani dulu.
            if (intent?.action == ACTION_WARNING_CLOSED) {
                // Dua pemicu Back: penanda dari alur blokir biasa, atau
                // permintaan eksplisit dari overlay (mode "sudah diblokir
                // permanen", yang dulu melompat ke layar Home).
                val diminta = intent.getBooleanExtra("request_back", false)
                if (backPendingAfterWarning || diminta) {
                    backPendingAfterWarning = false
                    // Overlay sudah benar-benar tertutup → aman kirim Back
                    // ke peramban, kembali ke halaman sebelumnya.
                    scheduleBackAfterBlock()
                }
                // Tampilkan kembali floating button setelah warning ditutup
                val currentBrowserUrl = readBrowserUrl()
                if (currentBrowserUrl.isNotBlank()) {
                    Handler(Looper.getMainLooper()).postDelayed({
                        floatingCheck?.show(currentBrowserUrl)
                    }, 800)
                }
                return
            }

            val targetUrl = intent?.getStringExtra("target_url") ?: return
            val normalized = normalizeUrl(targetUrl)

            when (intent.action) {
                ACTION_MARK_SAFE -> {
                    Log.d(TAG, "HITL ✅ User menandai AMAN: $normalized")
                    hitlWhitelistUrls.add(normalized)
                    saveUrlSet(PREF_WHITELIST, hitlWhitelistUrls)
                    // Reset warning tracker agar tidak re-trigger
                    if (normalizeUrl(warningShownForUrl) == normalized) {
                        warningShownForUrl = ""
                        lastDetectedUrl = ""
                    }
                }
                ACTION_MARK_THREAT -> {
                    Log.d(TAG, "HITL 🚫 User menandai PHISHING: $normalized")
                    hitlBlacklistUrls.add(normalized)
                    saveUrlSet(PREF_BLACKLIST, hitlBlacklistUrls)
                    saveToRoomBlacklist(normalized)
                    // Back dieksekusi saat WarningActivity selesai ditutup
                    // (lihat ACTION_WARNING_CLOSED) — bukan timer.
                    backPendingAfterWarning = true
                }
            }
        }
    }

    private val prefListener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ ->
        updateMonitoredPackages()
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        try {
            pipeline = AnalysisPipeline(this)
            prefs = AppPreferences(this)
            isReady = true
            floatingCheck = FloatingCheckManager(this)

            // Muat keputusan HITL pengguna dari sesi sebelumnya
            hitlBlacklistUrls.addAll(loadUrlSet(PREF_BLACKLIST))
            hitlWhitelistUrls.addAll(loadUrlSet(PREF_WHITELIST))
            Log.d(TAG, "HITL dimuat: ${hitlBlacklistUrls.size} blokir, ${hitlWhitelistUrls.size} aman")

            createAlertChannel()

            // Register HITL BroadcastReceiver untuk AMAN, BLOKIR & BLOKIR NOMOR
            val filter = IntentFilter().apply {
                addAction(ACTION_MARK_SAFE)
                addAction(ACTION_MARK_THREAT)
                addAction(ACTION_BLOCK_NUMBER)
                addAction(ACTION_IGNORE_MESSAGE)
                addAction(ACTION_REPORT_MESSAGE)
                addAction(ACTION_WARNING_CLOSED)
            }
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(hitlReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                registerReceiver(hitlReceiver, filter)
            }

            updateMonitoredPackages()
            prefs?.registerListener(prefListener)
            sendLogToUI("PhishGuard Service started.", "System", "SYSTEM")

            // ═ Firebase version-based sync (background, jangan block UI) ═
            FirebaseSyncManager(applicationContext).checkAndSync {
                Log.d(TAG, "Firebase sync selesai.")
                sendLogToUI("✅ Database cloud disinkronisasi.", "System", "SYSTEM")
                // Seed DB lokal dari feed phishing publik (OpenPhish + PhishTank)
                ServerSyncManager(applicationContext).syncAllPublicFeeds { added ->
                    Log.d(TAG, "Public feeds sync selesai (+$added).")
                    if (added > 0) sendLogToUI("✅ Database phishing +$added dari feed publik.", "System", "SYSTEM")
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error initializing service", e)
        }
    }

    private fun updateMonitoredPackages() {
        try {
            val info = serviceInfo ?: return
            val packages = prefs?.getMonitoredPackages()?.toMutableSet() ?: mutableSetOf()

            // Force-add: SMS bawaan selalu aktif
            packages.add("com.google.android.apps.messaging")
            packages.add("com.samsung.android.messaging")
            packages.add("com.android.mms")

            // Force-add: SEMUA browser yang didukung isBrowser check + BROWSER_URL_VIEW_IDS —
            // harus sinkron, kalau tidak event dari browser itu tidak akan pernah sampai
            // ke onAccessibilityEvent() sama sekali (di-filter OS di level packageNames).
            packages.add("com.android.chrome")
            packages.add("org.mozilla.firefox")
            packages.add("com.sec.android.app.sbrowser")
            packages.add("com.microsoft.emmx")
            packages.add("com.opera.browser")
            packages.add("com.opera.mini.native")
            packages.add("com.brave.browser")
            packages.add("com.duckduckgo.mobile.android")
            packages.add("com.mi.globalbrowser")
            packages.add("com.mi.globalbrowser.mini")
            packages.add("com.coloros.browser")
            packages.add("com.heytap.browser")
            packages.add("com.vivo.browser")
            packages.add("com.huawei.browser")
            packages.add("com.kiwibrowser.browser")
            packages.add("com.yandex.browser")
            packages.add("org.adblockplus.browser")
            packages.add("com.UCMobile.intl")
            packages.add("com.uc.browser.en")
            // In-app WebView browser (Facebook, TikTok, Twitter, YouTube)
            packages.add("com.facebook.katana")
            packages.add("com.zhiliaoapp.musically")
            packages.add("com.twitter.android")
            packages.add("com.google.android.youtube")

            info.packageNames = packages.toTypedArray()
            serviceInfo = info
            Log.d(TAG, "Updated monitored packages (${packages.size}): ${packages.joinToString()}")
        } catch (e: Exception) {
            Log.e(TAG, "Error updating monitored packages", e)
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (!isReady || event == null) return
        try {
            val packageName = event.packageName?.toString() ?: return
            val sourceName = getAppName(packageName)
            
            // Skip detection dari app PhishGuard sendiri (prevent recursive detection)
            if (packageName == "com.phishguard.ai") {
                return
            }

            // ══════════════════════════════════════════════
            // DETEKSI TIPE APP
            // ══════════════════════════════════════════════
            val isBrowser = when {
                // ─ Browser Utama ───────────────────────────────────
                packageName == "com.android.chrome"         -> true  // Google Chrome
                packageName == "com.sec.android.app.sbrowser" -> true // Samsung Internet
                packageName == "org.mozilla.firefox"        -> true  // Firefox
                packageName == "com.microsoft.emmx"         -> true  // Edge
                packageName == "com.opera.browser"          -> true  // Opera
                packageName == "com.opera.mini.native"      -> true  // Opera Mini
                packageName == "com.brave.browser"          -> true  // Brave
                packageName == "com.duckduckgo.mobile.android" -> true // DuckDuckGo
                // ─ Browser OEM (brand HP) ───────────────────────
                packageName == "com.mi.globalbrowser"       -> true  // Xiaomi Mi Browser
                packageName == "com.mi.globalbrowser.mini"  -> true  // Xiaomi Mini
                packageName == "com.coloros.browser"        -> true  // OPPO/ColorOS
                packageName == "com.heytap.browser"         -> true  // OPPO/Realme HeyTap
                packageName == "com.vivo.browser"           -> true  // Vivo Browser
                packageName == "com.huawei.browser"         -> true  // Huawei Browser
                packageName == "com.kiwibrowser.browser"    -> true  // Kiwi Browser
                packageName == "com.yandex.browser"         -> true  // Yandex Browser
                packageName == "org.adblockplus.browser"    -> true  // AdBlock Browser
                // ─ In-app Browser / WebView Sosmed ───────────────
                // (Facebook, YouTube, TikTok, Twitter buka link dalam in-app WebView)
                packageName == "com.facebook.katana"        -> true  // Facebook in-app
                packageName == "com.zhiliaoapp.musically"   -> true  // TikTok in-app
                packageName == "com.twitter.android"        -> true  // X/Twitter in-app
                packageName == "com.google.android.youtube" -> true  // YouTube in-app
                // UC Browser, dll
                packageName == "com.UCMobile.intl"          -> true
                packageName == "com.uc.browser.en"          -> true
                else -> false
            }

            if (isBrowser) {
                Log.v(TAG, "Browser event: pkg=$packageName type=${event.eventType}")

                // Loop-suppression: sesaat setelah blokir+back jangan re-scan
                // URL browser (mencegah warning muncul lagi saat halaman reload).
                if (System.currentTimeMillis() < backMuteUntil) {
                    Log.v(TAG, "Back-mute aktif, lewati scan browser.")
                    return
                }

                // Tampilkan floating "Check" button SEGERA begitu browser terdeteksi —
                // tidak menunggu URL bar berhasil terbaca (browser baru/custom sering
                // tidak match BROWSER_URL_VIEW_IDS, jadi jangan gate floating button
                // dengan keberhasilan parsing URL). URL asli akan mengisi currentUrl
                // begitu berhasil di-parse di bawah (floatingCheck?.show(analyzedUrl)).
                if (floatingCheck?.currentUrlOrEmpty()?.isBlank() != false) {
                    floatingCheck?.show("")
                }

                var rawUrl = ""

                // === STRATEGI 1: findAccessibilityNodeInfosByViewId (Paling Akurat) ===
                val rootNode = rootInActiveWindow
                if (rootNode != null) {
                    for (viewId in BROWSER_URL_VIEW_IDS) {
                        val nodes = rootNode.findAccessibilityNodeInfosByViewId(viewId)
                        if (nodes != null && nodes.isNotEmpty()) {
                            val node = nodes[0]
                            if (node != null) {
                                // MENCEGAH BLOKIR AGRESIF: 
                                // Jika URL bar sedang 'focused', artinya user masih mengetik.
                                // Kita tunda analisis sampai user selesai menekan Enter / merender page.
                                if (node.isFocused) {
                                    Log.d(TAG, "User sedang mengetik di URL bar, tunda analisis.")
                                    rootNode.recycle()
                                    return
                                }
                                
                                val text = node.text?.toString() ?: ""
                                if (text.isNotBlank()) {
                                    rawUrl = text
                                    Log.d(TAG, "Strategi 1 (viewId=$viewId) → $rawUrl")
                                    break
                                }
                            }
                        }
                    }
                    rootNode.recycle()
                }

                // === STRATEGI 2: Rekursif url_bar ===
                if (rawUrl.isBlank()) {
                    val rootNode2 = rootInActiveWindow
                    if (rootNode2 != null) {
                        val urlBuilder = StringBuilder()
                        extractBrowserUrl(rootNode2, urlBuilder)
                        if (urlBuilder.isNotEmpty()) {
                            rawUrl = urlBuilder.toString()
                            Log.d(TAG, "Strategi 2 (recursive) → $rawUrl")
                        }
                        rootNode2.recycle()
                    }
                }
                // Bilah alamat juga menampilkan kueri pencarian, judul halaman,
                // atau teks placeholder. Menganalisis itu sebagai URL hanya
                // menghasilkan peringatan palsu — saring dulu.
                if (!looksLikeUrl(rawUrl)) {
                    Log.v(TAG, "Bukan bentuk URL, lewati: ${rawUrl.take(40)}")
                    return
                }

                // UNWRAP AMP / redirect-wrapper: URL bar sering menunjukkan
                // "google.com/amp/s/<real-domain>/..." padahal domain phishing
                // tersembunyi di baliknya. Ekstrak host asli supaya deteksi
                // (brand, TLD, DB-by-domain) tidak tertipu oleh google.com.
                val analyzedUrl = unwrapRedirectUrl(rawUrl)
                if (analyzedUrl != rawUrl) {
                    Log.d(TAG, "Unwrapped redirect → $analyzedUrl (dari $rawUrl)")
                }

                val normalizedUrl = normalizeUrl(analyzedUrl)
                Log.d(TAG, "URL final: $normalizedUrl")

                // Tampilkan floating "Check" button saat browsing
                floatingCheck?.show(analyzedUrl)

                // Hindari memproses URL yang sama berulang
                if (normalizedUrl == normalizeUrl(lastDetectedUrl)) return
                lastDetectedUrl = rawUrl

                // CEK HITL WHITELIST
                if (hitlWhitelistUrls.contains(normalizedUrl)) {
                    Log.d(TAG, "HITL Whitelist bypass: $normalizedUrl")
                    return
                }

                // CEK HITL BLACKLIST
                if (hitlBlacklistUrls.contains(normalizedUrl)) {
                    Log.d(TAG, "HITL Blacklist hit: $normalizedUrl")
                    launchWarning(rawUrl, "URL ini telah dilaporkan sebagai phishing.", sourceName, true)
                    return
                }

                Log.d(TAG, "Kirim ke AnalysisPipeline: $normalizedUrl")
                
                // Increment scanned counter (every URL analyzed, safe or phishing)
                val prefs = getSharedPreferences("activity_log", Context.MODE_PRIVATE)
                val scannedCount = prefs.getInt("scanned_count", 0)
                prefs.edit().putInt("scanned_count", scannedCount + 1).apply()

                // Ambil sebagian teks halaman yang sedang diakses (accessibility root)
                // sebagai sinyal konten untuk layer wordlist/AI (deteksi judol dll).
                val pageSnippet = collectVisiblePageText(packageName)

                // Kirim URL yang sudah di-unwrap (host asli, bukan google.com/amp/s/...).
                // Tanpa ini AI menganalisis host pembungkus yang benign → semua deteksi
                // (brand, judol wordlist, hyphen) dilewati dan situs lolos.
                val targetUrl = analyzedUrl
                pipeline?.analyzeUrl(targetUrl, sourceName, pageSnippet) { result ->
                    handleAnalysisResult(result, targetUrl, sourceName)
                }

                // Halaman belum dirender saat ini. Periksa lagi setelah
                // isinya tampil — di situlah situs judol tanpa kata kunci
                // di domainnya baru bisa dikenali.
                scheduleContentRescan(targetUrl, sourceName, packageName)

            } else {
                // ═════════════════════════════════════
                // SMS / CHAT APPS — Smart 3-Layer Scan
                // ═════════════════════════════════════

                // Reset tracker saat user buka chat baru
                if (event.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
                    Log.d(TAG, " Window state changed — reset lastDetectedMessage & scan window")
                    lastDetectedMessage = ""
                    // Langsung scan window baru secara proactive
                    triggerWindowScan(packageName, sourceName)
                    return
                }

                // Hanya lanjut untuk event konten berubah
                if (event.eventType != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED &&
                    event.eventType != AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) return

                // "Abaikan" menahan pesan yang sama sampai konten berubah.
                // Window/content events setelah WarningActivity ditutup tidak
                // boleh membuka warning identik lagi.
                if (ignoredMessage.isNotBlank() &&
                    event.text?.joinToString(" ")?.trim() == ignoredMessage) return

                // ═ Ekstrak teks pesan dari event ═
                val rawEventText = event.text?.joinToString(" ")?.trim() ?: ""
                if (rawEventText.length < 20) return  // Skip event singkat (UI updates)

                // Filter teks yang bukan pesan (UI chrome Telegram, status, dsb)
                if (isChromeUIText(rawEventText)) {
                    Log.v(TAG, "Skip UI chrome text: ${rawEventText.take(30)}")
                    return
                }

                val messageText = rawEventText

                // Pesan baru membatalkan keputusan Abaikan sebelumnya.
                if (ignoredMessage.isNotBlank() && ignoredMessage != messageText) {
                    ignoredMessage = ""
                }

                // Hindari duplikasi analisis
                if (messageText == lastDetectedMessage) return
                lastDetectedMessage = messageText

                Log.d(TAG, "=== Chat Message BARU dari $sourceName ===")
                Log.d(TAG, "Msg: ${messageText.take(80)}...")

                pipeline?.analyzeMessageLayers(messageText, "", sourceName) { result ->
                    handleLayeredMessageResult(result, messageText, sourceName)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing accessibility event", e)
        }
    }

    /**
     * Algoritma rekursif ekstraksi URL dari riset phishing.
     * Mencari node dengan viewId yang mengandung "url_bar".
     */
    private fun extractBrowserUrl(node: AccessibilityNodeInfo?, urlBuilder: StringBuilder) {
        if (node == null) return
        val viewId = node.viewIdResourceName ?: ""
        if (viewId.contains("url_bar") || viewId.contains("omnibox_text")) {
            val rawText = node.text?.toString() ?: ""
            if (rawText.isNotBlank()) {
                urlBuilder.append(rawText)
                return // Sudah ketemu, tidak perlu lanjut rekursi di cabang ini
            }
        }
        for (i in 0 until node.childCount) {
            if (urlBuilder.isNotEmpty()) break // Sudah dapat URL, berhenti
            val child = node.getChild(i)
            extractBrowserUrl(child, urlBuilder)
            child?.recycle()
        }
    }

    /**
     * Normalisasi URL agar perbandingan whitelist/blacklist konsisten.
     * Hapus protokol (http/https), trailing slash, dan whitespace.
     */
    private fun normalizeUrl(url: String): String {
        return url.lowercase().trim()
            .removePrefix("https://")
            .removePrefix("http://")
            .trimEnd('/')
    }

    /**
     * Apakah teks ini berbentuk URL? Bilah alamat browser juga memuat kueri
     * pencarian ("tiket kereta murah") dan judul halaman. Syarat: satu kata,
     * ada titik, dan ada TLD huruf di hostname — atau berawalan skema.
     */
    private fun looksLikeUrl(text: String): Boolean {
        val t = text.trim()
        if (t.length < 4 || t.any { it.isWhitespace() }) return false
        if (t.startsWith("http://") || t.startsWith("https://")) return true
        val host = t.substringBefore('/').substringBefore('?')
        if (!host.contains('.')) return false
        return host.substringAfterLast('.').let { tld ->
            tld.length in 2..24 && tld.all { it.isLetterOrDigit() || it == '-' }
        }
    }

    /**
     * Ekspor host sebenarnya dari URL yang dibungkus AMP atau redirector.
     * Memperbaiki bypass "google.com/amp/s/<real-domain>/" dan
     * "apa-saja.com/go?url=https://<real-domain>/".
     */
    private fun unwrapRedirectUrl(url: String): String {
        val s = url.lowercase()

        // Parameter redirect: ?url=, &redirect=, ?target=, ?next=, ?u=, ?q=
        // (google.com/url?q=<target> adalah pembungkus redirect Google Search;
        //  tanpa q=, target phishing tersembunyi di balik google.com yang benign)
        Regex("""[?&](?:url|redirect|redirect_url|target|next|dest|u|q)=([^&]+)""")
            .find(s)?.groupValues?.get(1)?.let { encoded ->
                val decoded = try {
                    java.net.URLDecoder.decode(encoded, "UTF-8")
                } catch (e: Exception) {
                    encoded
                }
                val host = decoded.removePrefix("http://").removePrefix("https://")
                if (host.contains('.')) return host
            }

        // google.com/amp/s/<domain>/... dan google.com/amp/<domain>/...
        val ampIdx = s.indexOf("/amp/")
        if (ampIdx != -1) {
            val after = s.substring(ampIdx + 5)
            val cleaned = after.removePrefix("/s/").removePrefix("s/")
                .removePrefix("http://").removePrefix("https://")
            if (cleaned.isNotBlank() && cleaned.contains('.')) return cleaned
        }
        return url
    }

    /**
     * Kumpulkan sebagian teks dari halaman aktif (accessibility root) sebagai
     * sinyal konten untuk lapisan wordlist/AI. Dibatasi kapasitas agar tidak
     * memakan memori & tidak mem-bocorkan seluruh isi halaman.
     */
    // 1500 karakter terlalu sempit untuk menilai satu halaman: pada situs
    // judol nyata hanya satu istilah yang tertangkap sehingga skornya tak
    // pernah cukup. 6000 masih ringan (beberapa KB) tapi memuat cukup badan
    // halaman untuk menilai isinya.
    private fun collectVisiblePageText(expectedPackage: String, maxChars: Int = 6000): String {
        return try {
            val root = rootInActiveWindow ?: return ""
            // Jendela aktif WAJIB masih milik peramban yang sedang dinilai.
            //
            // Tanpa pemeriksaan ini, pemindaian yang tertunda membaca layar
            // apa pun yang sedang terbuka. Terbukti di perangkat: percakapan
            // WhatsApp terbaca dan diatribusikan ke sebuah URL judol. Dua
            // akibatnya sama-sama buruk — vonisnya jadi keliru, dan isi
            // percakapan pribadi ikut masuk mesin analisis.
            val actual = root.packageName?.toString()
            if (actual != expectedPackage) {
                root.recycle()
                Log.v(TAG, "Jendela aktif sudah pindah ke $actual, batalkan baca isi halaman")
                return ""
            }
            val sb = StringBuilder()
            collectNodeText(root, sb, maxChars)
            root.recycle()
            sb.toString().trim().take(maxChars)
        } catch (e: Exception) {
            Log.e(TAG, "collectVisiblePageText error", e)
            ""
        }
    }

    private fun collectNodeText(node: AccessibilityNodeInfo?, sb: StringBuilder, cap: Int) {
        if (node == null || sb.length >= cap) return
        val text = node.text?.toString()?.trim()
        if (!text.isNullOrBlank()) {
            sb.append(' ').append(text)
            if (sb.length > cap) return
        }
        for (i in 0 until node.childCount) {
            if (sb.length >= cap) break
            val child = node.getChild(i)
            collectNodeText(child, sb, cap)
            child?.recycle()
        }
    }

    /**
     * Setelah konfirmasi "Ya, Blokir": tunggu warning Activity selesai (finish),
     * lalu kirim Back global (GLOBAL_ACTION_BACK) supaya browser kembali satu
     * halaman. Set mute-window agar page yang reload tak langsung warning lagi.
     */
    private fun scheduleBackAfterBlock() {
        val blockedUrl = normalizeUrl(warningShownForUrl)
        Handler(Looper.getMainLooper()).postDelayed({
            try {
                val ok = performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
                backMuteUntil = System.currentTimeMillis() + BACK_MUTE_MS
                Log.d(TAG, "Back-after-block executed=$ok")

                // Tab yang dibuka langsung dari tautan (WhatsApp, SMS) tidak
                // punya riwayat, jadi Back tidak punya tujuan dan pengguna
                // tertinggal di situs berbahaya — peringatan lalu muncul
                // berulang. Periksa hasilnya, dan hanya kalau Back terbukti
                // gagal, mundur ke layar utama.
                Handler(Looper.getMainLooper()).postDelayed({
                    verifyLeftBlockedSite(blockedUrl, attempt = 1)
                }, BACK_VERIFY_MS)
            } catch (e: Exception) {
                Log.e(TAG, "back-after-block error", e)
            }
        }, 600)
    }

    /**
     * Masih di URL yang sama setelah Back? Berarti tab itu tanpa riwayat.
     *
     * Diperiksa dua kali sebelum menyimpulkan. Pada jaringan lambat, Back
     * ke halaman sebelumnya butuh waktu; sekali periksa bisa keliru menilai
     * "tanpa riwayat" lalu memulangkan pengguna ke layar utama padahal
     * Back-nya sebentar lagi berhasil.
     */
    private fun verifyLeftBlockedSite(blockedUrl: String, attempt: Int) {
        if (blockedUrl.isBlank()) return
        val current = normalizeUrl(readBrowserUrl())
        if (current.isBlank() || current != blockedUrl) {
            Log.d(TAG, "Back berhasil meninggalkan situs.")
            return
        }
        if (attempt < BACK_VERIFY_ATTEMPTS) {
            Handler(Looper.getMainLooper()).postDelayed({
                verifyLeftBlockedSite(blockedUrl, attempt + 1)
            }, BACK_VERIFY_MS)
            return
        }
        Log.d(TAG, "Back tidak punya halaman tujuan — mundur ke layar utama.")
        try {
            performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME)
            backMuteUntil = System.currentTimeMillis() + BACK_MUTE_MS
        } catch (e: Exception) {
            Log.e(TAG, "fallback home error", e)
        }
    }

    /** Baca URL dari bilah alamat peramban yang sedang tampil. */
    private fun readBrowserUrl(): String {
        return try {
            val root = rootInActiveWindow ?: return ""
            var found = ""
            for (viewId in BROWSER_URL_VIEW_IDS) {
                val nodes = root.findAccessibilityNodeInfosByViewId(viewId)
                if (!nodes.isNullOrEmpty()) {
                    val text = nodes[0]?.text?.toString().orEmpty()
                    if (text.isNotBlank()) { found = text; break }
                }
            }
            root.recycle()
            found
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Respons BERTINGKAT sesuai keyakinan — perbaikan utama pengalaman pakai.
     *
     * Sebelumnya setiap deteksi, sekuat apa pun sinyalnya, langsung membajak
     * layar dengan overlay merah. Satu tebakan meleset = pengguna terjegal.
     * Sekarang:
     *   DANGEROUS (≥0,80) → overlay layar penuh, situs benar-benar dihentikan
     *   SUSPICIOUS       → notifikasi yang bisa diabaikan, browsing jalan terus
     *   selain itu       → hanya masuk log
     */
    /**
     * Periksa ulang URL yang sama setelah halamannya sempat dirender.
     *
     * Hanya MENAIKKAN vonis: kalau pemindaian kedua menilai aman, hasilnya
     * diabaikan diam-diam. Vonis pertama sudah dilaporkan, dan menurunkannya
     * di belakang layar hanya akan membingungkan.
     */
    private fun scheduleContentRescan(url: String, source: String, browserPackage: String) {
        pendingRescan?.let { rescanHandler.removeCallbacks(it) }
        var attempt = 0
        lateinit var task: Runnable
        task = Runnable {
            attempt++
            // Pengguna sudah pindah halaman — pemindaian tak relevan lagi.
            if (normalizeUrl(lastDetectedUrl) != normalizeUrl(url)) return@Runnable
            if (System.currentTimeMillis() < backMuteUntil) return@Runnable

            val text = collectVisiblePageText(browserPackage)
            if (text.length < MIN_PAGE_TEXT) {
                // Halaman masih kosong; coba sekali lagi, jangan lebih.
                if (attempt < RESCAN_ATTEMPTS) rescanHandler.postDelayed(task, RESCAN_DELAY_MS)
                return@Runnable
            }

            Log.d(TAG, "Pindai ulang isi halaman $url (${text.length} karakter)")
            pipeline?.analyzeUrl(url, source, text) { result ->
                if (result.isThreat) handleAnalysisResult(result, url, source)
            }
        }
        pendingRescan = task
        rescanHandler.postDelayed(task, RESCAN_DELAY_MS)
    }

    private fun handleAnalysisResult(result: AnalysisResult, item: String, source: String) {
        if (!result.isThreat) {
            sendLogToUI("✅ Aman: ${item.take(80)}", source, "SAFE")
            if (normalizeUrl(item) == normalizeUrl(warningShownForUrl)) {
                warningShownForUrl = ""
            }
            return
        }

        val dangerous = result.metadata["level"] == "DANGEROUS" ||
                result.confidence >= UrlRiskScorer.THRESHOLD_DANGEROUS

        if (dangerous) {
            sendLogToUI("⚠️ ${result.threatType}: ${item.take(80)} — ${result.reason}", source, "PHISHING")
            launchWarning(item, result.reason, source, confidence = result.confidence)
        } else {
            sendLogToUI("🟡 Mencurigakan: ${item.take(80)} — ${result.reason}", source, "SUSPICIOUS")
            notifySuspicious(item, result.reason, result.confidence)
        }
    }

    /**
     * Peringatan lunak: notifikasi, bukan overlay. Pengguna tetap memegang
     * kendali — bisa lanjut, atau membuka detail untuk memblokir.
     */
    private fun notifySuspicious(url: String, reason: String, confidence: Float) {
        try {
            val host = url.removePrefix("https://").removePrefix("http://").substringBefore('/')
            val detail = Intent(this, WarningActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                putExtra(WarningActivity.EXTRA_PHISHING_URL, url)
                putExtra(WarningActivity.EXTRA_REASON, reason)
                putExtra(WarningActivity.EXTRA_SOURCE, "Browser")
                putExtra(WarningActivity.EXTRA_CONFIDENCE, confidence)
            }
            val pending = PendingIntent.getActivity(
                this, url.hashCode(), detail,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val notif = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("Situs perlu diperiksa: $host")
                .setContentText(reason)
                .setStyle(NotificationCompat.BigTextStyle().bigText("$reason\n\nKetuk untuk melihat detail dan memblokir bila memang penipuan."))
                .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                .setColor(0xFFF59E0B.toInt())
                .setAutoCancel(true)
                .setContentIntent(pending)
                .build()
            NotificationManagerCompat.from(this).notify(url.hashCode(), notif)
        } catch (e: Exception) {
            Log.e(TAG, "notifySuspicious error", e)
        }
    }

    private fun createAlertChannel() {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.O) return
        val channel = android.app.NotificationChannel(
            ALERT_CHANNEL_ID,
            "Peringatan situs mencurigakan",
            android.app.NotificationManager.IMPORTANCE_DEFAULT
        ).apply { description = "Situs dengan sinyal mencurigakan tapi belum pasti berbahaya" }
        getSystemService(android.app.NotificationManager::class.java)
            ?.createNotificationChannel(channel)
    }

    /**
     * Proactive scan saat user membuka window chat baru.
     * Mengambil SEMUA teks pesan yang sudah terlihat di layar.
     */
    private fun triggerWindowScan(packageName: String, sourceName: String) {
        // Use non-blocking delay to allow UI to render before scanning
        Handler(Looper.getMainLooper()).postDelayed({
            try {
                val rootNode = rootInActiveWindow ?: run {
                    Log.w(TAG, "triggerWindowScan: rootInActiveWindow = null")
                    return@postDelayed
                }
                val messages = mutableListOf<String>()
                collectAllMessageNodes(rootNode, messages, packageName)
                rootNode.recycle()

                Log.d(TAG, "Proactive scan: ${messages.size} teks ditemukan di $sourceName")

                // Analisis SEMUA teks yang substansial (bukan hanya terpanjang)
                val candidates = messages.filter { it.length > 20 && !isChromeUIText(it) }
                if (candidates.isEmpty()) return@postDelayed

                // Ambil teks terpanjang sebagai pesan terbaik
                val bestMessage = candidates.maxByOrNull { it.length } ?: return@postDelayed
                Log.d(TAG, "Scan terbaik: ${bestMessage.take(80)}")

                // Jalur proactive scan juga harus menghormati "Abaikan".
                if (bestMessage == ignoredMessage) {
                    Log.d(TAG, "Pesan diabaikan, skip proactive scan.")
                    return@postDelayed
                }

                lastDetectedMessage = bestMessage
                pipeline?.analyzeMessageLayers(bestMessage, "", sourceName) { result ->
                    handleLayeredMessageResult(result, bestMessage, sourceName)
                }
            } catch (e: Exception) {
                Log.e(TAG, "triggerWindowScan error", e)
            }
        }, 500)
    }

    /**
     * Kumpulkan semua teks dari node AccessibilityTree yang terlihat seperti pesan.
     * Lebih agresif dari collectMessageText — dipakai saat buka chat baru.
     */
    private fun collectAllMessageNodes(
        node: AccessibilityNodeInfo?,
        results: MutableList<String>,
        pkg: String,
        depth: Int = 0
    ) {
        if (node == null || depth > 20) return

        // Ambil dari node.text ATAU node.contentDescription
        // Telegram sering menyimpan teks + link di contentDescription
        val rawText = node.text?.toString()?.trim() ?: ""
        val rawDesc = node.contentDescription?.toString()?.trim() ?: ""
        val className = node.className?.toString() ?: ""

        // Tambahkan semua sumber teks ke results (filter dilakukan di triggerWindowScan)
        if (rawText.length > 10) results.add(rawText)
        if (rawDesc.length > 10 && rawDesc != rawText) results.add(rawDesc)

        for (i in 0 until node.childCount) {
            val child = node.getChild(i) ?: continue
            collectAllMessageNodes(child, results, pkg, depth + 1)
            child.recycle()
        }
    }

    /**
     * Filter teks UI chrome dari Telegram/chat apps yang bukan isi pesan.
     * Contoh: "terlihat belakangan ini", "online", "diketik...", timestamp singkat.
     */
    private fun isChromeUIText(text: String): Boolean {
        val lc = text.lowercase().trim()
        if (lc == "terlihat belakangan ini") return true
        if (lc == "online") return true
        if (lc == "mengetik...") return true
        if (lc == "sedang merekam...") return true
        if (lc == "lang") return true
        if (lc.length <= 10) return true
        // Timestamp "11:04" atau "10:19"
        if (lc.matches(Regex("\\d{1,2}:\\d{2}"))) return true
        // Tanggal "9 Maret" atau "9 March"
        if (lc.matches(Regex("\\d{1,2}\\s+\\w+"))) return true
        return false
    }

    /**
     * Handler untuk hasil 3-Layer Pipeline.
     * Setiap layer yang detect threat memunculkan HITL overlay.
     */
    private fun handleLayeredMessageResult(result: LayeredResult, originalText: String, source: String) {
        if (!result.isThreat) {
            sendLogToUI("✅ Pesan aman dari $source", source, "SAFE")
            return
        }

        val (title, detail, extraKey) = when (result.layer) {
            ThreatLayer.URL -> Triple(
                "🔴 Link Berbahaya di Pesan!",
                "Pesan dari $source mengandung URL phishing.\n\nURL: ${result.detectedValue}\n\n${result.reason}",
                "layer_url"
            )
            ThreatLayer.NUMBER -> Triple(
                "🚨 Nomor Penipu Terdeteksi!",
                "Nomor pengirim terdapat di database penipu.\n\nNomor: ${result.detectedValue}\n\n${result.reason}",
                "layer_number"
            )
            ThreatLayer.CONTENT -> Triple(
                "⚠️ Pola Penipuan Terdeteksi!",
                "Isi pesan mengandung pola penipuan.\n\n${result.reason}\n\nSkor: ${(result.confidence * 100).toInt()}%",
                "layer_content"
            )
            null -> Triple("⚠️ Ancaman Terdeteksi", result.reason, "layer_unknown")
        }

        sendLogToUI("$title - $source", source, "SCAM")
        launchMessageWarning(
            messageText = originalText.take(150),
            ignoredText = originalText,
            reason = "$title\n\n$detail",
            source = source,
            extraThreatLayer = extraKey
        )
    }

    private fun launchWarning(
        url: String,
        reason: String,
        source: String,
        isPermanentBlock: Boolean = false,
        confidence: Float = 0.9f
    ) {
        try {
            warningShownForUrl = url
            floatingCheck?.hide() // Sembunyikan saat warning muncul
            val intent = Intent(this, WarningActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                putExtra(WarningActivity.EXTRA_PHISHING_URL, url)
                putExtra(WarningActivity.EXTRA_REASON, reason)
                putExtra(WarningActivity.EXTRA_SOURCE, source)
                putExtra(WarningActivity.EXTRA_IS_PERMANENT_BLOCK, isPermanentBlock)
                putExtra(WarningActivity.EXTRA_CONFIDENCE, confidence)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error launching warning", e)
        }
    }

    private fun launchMessageWarning(
        messageText: String,
        ignoredText: String = messageText,
        reason: String,
        source: String,
        extraThreatLayer: String = ""
    ) {
        try {
            val extractedPhone = extractPhoneFromSource(source)
            Log.d(TAG, "=== launchMessageWarning DEBUG ===")
            Log.d(TAG, "source: '$source'")
            Log.d(TAG, "extractedPhone: '$extractedPhone'")
            
            val intent = Intent(this, WarningActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                putExtra(WarningActivity.EXTRA_PHISHING_URL, messageText)
                putExtra(WarningActivity.EXTRA_REASON, reason)
                putExtra(WarningActivity.EXTRA_SOURCE, source)
                putExtra("ignored_message", ignoredText)
                putExtra("is_sms_mode", true)
                putExtra("phone_number", extractedPhone)
                putExtra("threat_layer", extraThreatLayer)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Error launching message warning", e)
        }
    }
    
    // Extract phone number from source string like "SMS (08123456789)"
    private fun extractPhoneFromSource(source: String): String {
        val regex = """\(([+\d]+)\)""".toRegex()
        return regex.find(source)?.groupValues?.get(1) ?: ""
    }

    // Simpan / muat keputusan HITL (blokir maupun aman) agar persisten
    private fun saveUrlSet(key: String, urls: Set<String>) {
        try {
            getSharedPreferences("phishguard_blacklist", Context.MODE_PRIVATE)
                .edit().putStringSet(key, urls.toSet()).apply()
            Log.d(TAG, "HITL $key disimpan (${urls.size} entri)")
        } catch (e: Exception) {
            Log.e(TAG, "Error saving $key", e)
        }
    }

    private fun loadUrlSet(key: String): Set<String> = try {
        getSharedPreferences("phishguard_blacklist", Context.MODE_PRIVATE)
            .getStringSet(key, emptySet()) ?: emptySet()
    } catch (e: Exception) {
        Log.e(TAG, "Error loading $key", e)
        emptySet()
    }

    /**
     * Tombol "Blokir Nomor" di overlay SMS. Sebelumnya broadcast ini tidak
     * punya penerima sama sekali — nomor hanya tercatat di log dan tidak
     * pernah masuk database, sehingga SMS berikutnya lolos lagi.
     */
    private fun blockPhoneNumber(number: String) {
        kotlin.concurrent.thread {
            try {
                PhishingDatabase.getInstance(applicationContext).phishingNumberDao().insert(
                    PhishingNumber(
                        number = number,
                        reason = "Diblokir oleh pengguna via HITL",
                        source = "user_report",
                        confidence = 1.0f
                    )
                )
                Log.d(TAG, "Nomor diblokir & disimpan ke DB: $number")
                sendLogToUI("🚫 Nomor $number diblokir.", "SMS", "PHISHING")
            } catch (e: Exception) {
                Log.e(TAG, "Gagal menyimpan nomor blokir", e)
            }
        }
    }

    // Simpan URL ke Room Database phishing_urls
    private fun saveToRoomBlacklist(url: String) {
        try {
            kotlin.concurrent.thread {
                val db = PhishingDatabase.getInstance(applicationContext)
                val hostname = url.removePrefix("https://").removePrefix("http://").split("/").first()
                db.phishingUrlDao().insert(
                    PhishingUrl(
                        url = url,
                        domain = hostname,
                        reason = "Dilaporkan oleh pengguna via HITL",
                        source = "user_report",
                        confidence = 1.0f
                    )
                )
                Log.d(TAG, "URL disimpan ke Room DB: $url")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error saving to Room DB", e)
        }
    }

    override fun onInterrupt() {
        Log.d(TAG, "Service interrupted")
    }

    override fun onDestroy() {
        super.onDestroy()
        rescanHandler.removeCallbacksAndMessages(null)
        prefs?.unregisterListener(prefListener)
        try { unregisterReceiver(hitlReceiver) } catch (e: Exception) {}
        pipeline?.release()
        floatingCheck?.destroy()
        isReady = false
    }

    private fun sendLogToUI(message: String, source: String, type: String) {
        try {
            // setPackage: log memuat URL yang dikunjungi pengguna — jangan
            // disiarkan sebagai broadcast implisit yang bisa dibaca app lain.
            val intent = Intent("com.phishguard.ai.LOG_UPDATE").apply {
                setPackage(packageName)
                putExtra("message", message)
                putExtra("source", source)
                putExtra("type", type)
            }
            sendBroadcast(intent)

            // Persist ke activity_log agar gap deteksi tampak di log (SAFE ikut masuk)
            val prefs = getSharedPreferences("activity_log", Context.MODE_PRIVATE)
            val existing = (prefs.getStringSet("logs", emptySet()) ?: emptySet()).toMutableList()
            val safeMessage = message.replace('|', ' ')
            existing.add("${System.currentTimeMillis()}|$safeMessage|$source|$type")
            // Buang yang PALING LAMA. Versi lama memangkas Set tanpa urutan,
            // jadi entri yang terhapus acak — kadang justru yang terbaru.
            val trimmed = existing
                .sortedByDescending { it.substringBefore('|').toLongOrNull() ?: 0L }
                .take(200).toSet()
            prefs.edit().putStringSet("logs", trimmed).apply()
        } catch (e: Exception) {}
    }

    companion object {
        const val ACTION_MARK_SAFE    = "com.phishguard.ai.MARK_SAFE"
        const val ACTION_MARK_THREAT  = "com.phishguard.ai.MARK_THREAT"
        const val ACTION_BLOCK_NUMBER = "com.phishguard.ai.BLOCK_NUMBER"
        const val ACTION_IGNORE_MESSAGE = "com.phishguard.ai.IGNORE_MESSAGE"
        const val ACTION_REPORT_MESSAGE = "com.phishguard.ai.REPORT_MESSAGE"
        const val ACTION_WARNING_CLOSED = "com.phishguard.ai.WARNING_CLOSED"

        private const val PREF_BLACKLIST = "urls"
        private const val PREF_WHITELIST = "safe_urls"
        private const val ALERT_CHANNEL_ID = "phishguard_suspicious"

        /** id bilah alamat tiap peramban, dipakai analisis dan verifikasi Back. */
        private val BROWSER_URL_VIEW_IDS = listOf(
            "com.android.chrome:id/url_bar",
            "com.sec.android.app.sbrowser:id/location_bar_edit_text",
            "org.mozilla.firefox:id/url_bar_title",
            "org.mozilla.firefox:id/mozac_browser_toolbar_url_view",
            "com.microsoft.emmx:id/url_bar",
            "com.opera.browser:id/url_field",
            "com.opera.mini.native:id/url_field",
            "com.brave.browser:id/url_bar",
            "com.duckduckgo.mobile.android:id/omnibarTextInput",
            "com.mi.globalbrowser:id/url",
            "com.mi.globalbrowser.mini:id/url",
            "com.coloros.browser:id/address_editor_text",
            "com.heytap.browser:id/address_editor_text",
            "com.vivo.browser:id/address",
            "com.huawei.browser:id/url_bar",
            "com.kiwibrowser.browser:id/url_bar",
            "com.yandex.browser:id/bro_omnibox_address_title_text",
            "com.UCMobile.intl:id/address_bar_edit_text",
            "com.uc.browser.en:id/address_bar_edit_text"
        )

        /** Bisu sesaat setelah Back agar halaman yang memuat ulang tak memicu ulang. */
        private const val BACK_MUTE_MS = 3500L
        /** Jeda sebelum memastikan Back benar-benar meninggalkan situs. */
        private const val BACK_VERIFY_MS = 1400L
        /** Berapa kali diperiksa sebelum menyimpulkan Back tak punya tujuan. */
        private const val BACK_VERIFY_ATTEMPTS = 2

        /** Jeda sebelum isi halaman diperiksa ulang. */
        private const val RESCAN_DELAY_MS = 2500L
        /** Berapa kali menunggu halaman terisi sebelum menyerah. */
        private const val RESCAN_ATTEMPTS = 3
        /** Di bawah ini teksnya masih antarmuka peramban, bukan isi halaman. */
        private const val MIN_PAGE_TEXT = 300
    }

    private fun getAppName(packageName: String): String {
        return when (packageName) {
            "com.android.chrome" -> "Chrome"
            "org.mozilla.firefox" -> "Firefox"
            "com.sec.android.app.sbrowser" -> "Samsung Internet"
            "com.whatsapp" -> "WhatsApp"
            "org.telegram.messenger" -> "Telegram"
            "com.facebook.orca" -> "Messenger"
            "com.instagram.android" -> "Instagram"
            else -> packageName.substringAfterLast(".")
        }
    }
}
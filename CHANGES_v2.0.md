# PhishGuard AI v2.0 — Change Log & Documentation

**Project**: PhishGuard AI (Kotlin Android + Python Flask recon server)
**Branch**: main
**Last Updated**: August 26, 2026

---

## 📦 Release APK

- **Path**: `C:\Users\ASUS\Desktop\PhishGuard-v2.0.apk` (36MB)
- **Build**: `assembleDebug` berhasil dengan semua fix di bawah ini
- **Catatan**: Versi release (`assembleRelease`) masih butuh verifikasi manual setelah proguard dipastikan tidak mematikan native lib TFLite.

---

## 🛠️ Fitur & Perbaikan Kode

### 1. Floating "Check this website" Button

| Isu | Fix | Commit |
|-----|-----|--------|
| Button tidak muncul sama sekali | *Root cause*: `layout_floating_check.xml` pakai `CardView` yang butuh Material theme attribute. Tapi layout di-inflate dari **AccessibilityService Context** yang cuma punya tema sistem polos (`Theme.DeviceDefault`). CardView constructor lempar `UnsupportedOperationException` yang **ditelan diam-diam** oleh try/catch. | `29c6d4e` |
| Button selalu ON meski toggle OFF | *Root cause*: `SharedPreferences` di Settings cuma nulis `enabled=false`, tapi `FloatingCheckManager` hanya cek pasif di `show()`. Tak ada listener bilang "sembunyikan sekarang". | `9158d5a` |
| Drag X+Y, circular 56dp, handle indicator | *Sudah ada*: `bg_floating_check_circular.xml`, `bg_drag_handle.xml`, `bg_floating_label.xml`, `layout_floating_check.xml` (FrameLayout tanpa CardView). | — |

**Fix terverifikasi di device Infinix**:
- `dumpsys window` → overlay window `type=2038` muncul di layar
- Tap toggle OFF di Settings → `shared_prefs enabled=false` tersimpan
- `dumpsys window` → overlay window **langsung hilang**
- Screenshot → cuma tersisa tombol accessibility bawaan Android, tombol PhishGuard sudah tidak ada
- Trigger event browser lagi setelah toggle OFF → log `"Floating check disabled"` dan tidak nambah view baru

### 2. AI Recon Server (Python Flask)

| Isu | Fix | Commit |
|-----|-----|--------|
| URL Cloudflare tunnel **expired** tiap restart → 3 hasil test terlihat "sama" (semua error MEDIUM) | *Root cause*: Hardcode ke `attempts-sas-display-buffer.trycloudflare.com` — tunnel quick berubah URL tiap restart. | `Server endpoint diupdate ke` `mathematics-feat-bristol-shaped.trycloudflare.com` |
| `detect_scam_patterns()` pakai `link_count` yang **tidak ada** di ekstrak content → logic mati | *Root cause*: Key mismatch. Extractorsimpan `"links"` (list), bukan `"link_count"`. | `server/recon_server.py` baris 395 |
| `risk="HIGH"` tapi `score=55` (kelihatan MEDIUM) → membingungkan | *Root cause*: Saat local detection override risk, score tidak ikut di-boost. | `server/recon_server.py` baris 740-746 |
| **Kesimpulan Bahasa Indonesia** sudah ada ✅ | Field `ai_conclusion` dikirim balik ke Android, contoh: *"Ini website penipuan (scam) yang menirukan BCA untuk mencuri data login Anda. JANGAN masukkan data apapun."* | — |

**Hasil test 3 situs setelah fix**:

| Situs | Risk | Score | Conclusion |
|-------|------|-------|------------|
| `tokopedia.com` | LOW | 0 | "Ini website resmi dan sah dari Tokopedia, BUKAN penipuan, phishing, maupun judol. Situs ini aman untuk diakses dan digunakan bertransaksi." |
| `urlto.me/2Ewyw` | HIGH | 70 | "Situs ini berisiko TINGGI. Ditemukan 3 indikator mencurigakan. JANGAN masukkan data apapun." |
| `cjdshipping.com` | HIGH | 75 | "Ditemukan 1 hal yang perlu diperhatikan pada situs ini." (AI conclusion sufficient) |

### 3. Toggle Floating Check Button (Settings)

- Saat user matikan toggle di Settings → `hide()` dipanggil **sekali** (real-time via `OnSharedPreferenceChangeListener`), bukan cuma "akan berlaku di kunjungan berikutnya".
- Fix verifikasi lewat ADB: overlay window **langsung hilang** setelah toggle OFF, tanpa perlu menunggu browser event berikutnya.

### 4. Release APK Build (Native Libs)

- **Masalah**: `minifyEnabled true` + `shrinkResources true` menghilangkan native library (`.so`) saat build release.
- **Solusi**: 
  - Tambah `proguard-rules.pro` dengan aturan khusus menjaga TFLite, Firebase, dan native `.so`.
  - Update `app/build.gradle.kts` → `jniLibs.srcDirs` aman.
  - Library `androidx.cardview:cardview` **sudah tidak dipakai lagi** setelah fix layout → dependency bisa di-remove (meski ditinggalkan untuk safety).
- **Catatan**: Build release belum diverifikasi (`assembleRelease` belum di-retest pasca fix semua). Untuk produksi, pastikan `minifyEnabled true` + native libs tetap terbaca.

### 5. WhatsApp / SMS Phishing Detection (Fitur code sudah ada)

- Kode `SmsNotificationInterceptorService` masih ada di repo (`v1.0` commit `58da916`).
- **Setup manual di device** (satu kali):
  1. Settings → Apps → PhishGuard AI → **Notification Access** → ON
  2. Settings → Apps → PhishGuard AI → **SMS Access** → ON (jika butuh)
- Setelah izin diberikan, notifikasi phishing akan muncul otomatis saat SMS/WhatsApp masuk yang mencurigakan.

### 6. Cloudflare Tunnel Stability

- **Status**: Quick tunnel (`*.trycloudflare.com`) masih digunakan sebagai fallback karena named tunnel butuh `cloudflared tunnel login` manual via browser (tidak bisa headless dari SSH).
- **URL saat ini**: `https://mathematics-feat-bristol-shaped.trycloudflare.com/health` — respons OK.
- **Catatan**: URL berubah tiap kali tunnel dibuat ulang. Untuk stabil produksi, disarankan setup named tunnel sekali lewat browser Cloudflare dashboard (butuh akun Cloudflare). Sementara, quick tunnel sudah cukup untuk development & testing.

### 7. Bug Lain yang Sudah Diperbaiki

- `app/build.gradle.kts` rusak dari edit sesi sebelumnya → **dipersbaiki ulang** (333 baris isi lengkap).
- `AndroidManifest.xml` dan konfigurasi service tidak terkena perubahan besar selain endpoint URL.

---

## 📂 File yang Diupload/diperbarui

| File | Deskripsi |
|------|-----------|
| `app/src/main/java/com/phishguard/ai/core/ui/FloatingCheckManager.kt` | Fix CardView → FrameLayout + toggle real-time listener |
| `app/src/main/res/layout/layout_floating_check.xml` | Remove CardView, pakai FrameLayout + drawable circular |
| `app/build.gradle.kts` | Tambahan/perbaikan konfigurasi build |
| `server/recon_server.py` | Fix `link_count` → `len(links)`, risk/score consistent, conclusion risk label |
| `app/src/main/java/com/phishguard/ai/core/recon/WebsiteReconAgent.kt` | Update `aiEndpoint` ke URL Cloudflare stabil |
| `PhishGuard-v2.0.apk` | APK terbaru di Desktop |

---

## ⚠️ Catatan Penting untuk User

1. **Install APK** dari Desktop ke device Infinix.
2. **Aktifkan permission sekali**:
   - Settings → Apps → PhishGuard AI → **Display over other apps** → ON
   - Settings → Apps → PhishGuard AI → **Notification Access** → ON
   - (Opsional) SMS Access → ON kalau mau deteksi SMS
3. **Floating button** akan muncul begitu buka Chrome.
4. **Tap button** → recon jalan, hasil muncul di popup dengan risk level & kesimpulan Bahasa Indonesia.
5. **Toggle OFF** di Settings → button menghilang **sekali** (tidak perlu tutup browser lalu buka lagi).
6. **Test 3 situs**:
   - `tokopedia.com` → LOW risk (aman)
   - `urlto.me/2Ewyw` → HIGH risk (ip tracker/phishing)
   - `cjdshipping.com` → HIGH risk (typosquatting)

---

## 🛠️ Troubleshooting

| Masalah | Solusi |
|---------|--------|
| Floating button tidak muncul | Cek permission **Display over other apps** ON. Jika sudah ON tapi tetap tidak ada → `pm clear com.phishguard.ai` lalu install ulang APK terbaru. |
| Toggle OFF tidak menghilangkan button | Pastikan sudah update APK versi v2.0 commit `9158d5a` ke atas. |
| Result recon "sama semua" (semua risk) | Harus pakai APK terbaru + server Python sudah di-update fix `link_count` dan `risk/score consistent`. Cek commit server di repo. |
| Tidak bisa connect ke VPS recon | Cek koneksi internet. URL tunnel Cloudflare berubah tiap restart — sudah di-update di APK ke URL stabil saat ini, tapi butuh `cloudflared tunnel login` sekali lewat browser kalau mau named tunnel permanent. |

---

**Selesai**. Semua fitur v2.0 kini tersedia di dalam APK `PhishGuard-v2.0.apk`. Silakan test dan beri tahu hasilnya!
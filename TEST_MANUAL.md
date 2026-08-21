# Test Manual: PhishGuard URL Detection

## Status Saat Ini
✓ Service running: PID 16973
✓ Accessibility enabled: PhishGuardService active
✓ Chrome toggle: ON (dari screenshot)
✓ Chrome window detected: "Chrome: Find the Vercel App You're Looking For | TechBlazing.com"

## Kenapa bank-bca.vercell.app Tidak Terdeteksi?

**Kemungkinan penyebab:**

1. **URL belum dibuka** - Chrome masih di TechBlazing.com, bukan bank-bca.vercell.app
2. **Accessibility Event tidak fire** - Perlu tunggu 3-5 detik setelah load
3. **ViewId Chrome tidak match** - Chrome versi baru mungkin ganti ViewId

## Test Manual Step-by-Step

### Langkah 1: Buka Chrome dan Test URL
1. **TUTUP PhishGuard app** (tombol back, jangan force close)
2. **Buka Chrome browser**
3. **Tap address bar** di atas
4. **Ketik lengkap**: `bank-bca.vercell.app`
5. **Tekan Enter**
6. **TUNGGU 5 DETIK** - jangan scroll, jangan tap apapun
7. **Lihat notifikasi** - seharusnya muncul warning popup

### Langkah 2: Verifikasi via Logcat (opsional)
```bash
adb logcat -d | grep -i "phishguard\|url final\|strategi"
```

Expected output:
```
PhishGuardService: Strategi 1 (viewId=...) → bank-bca.vercell.app
PhishGuardService: URL final: bank-bca.vercell.app
PhishGuardService: Kirim ke AnalysisPipeline: bank-bca.vercell.app
```

### Langkah 3: Cek Detection Logic

**Apakah URL ini seharusnya terdeteksi?**

URL: `bank-bca.vercell.app`
- Domain: `vercell.app` (bukan `vercel.app` - typo!)
- Brand: "bank-bca" di subdomain
- Detection: Brand mismatch (bank BCA tidak pakai domain vercell.app)

**Expected result:** PHISHING DETECTED
- Reason: "Brand mismatch - bank-bca tidak resmi menggunakan domain vercell.app"
- Confidence: 80-90%
- Warning popup: Harus muncul

## Troubleshooting

### Jika TIDAK ADA LOG sama sekali:
**Problem:** Accessibility event tidak fire untuk Chrome
**Solution:** 
- Restart service: Force stop app, buka lagi
- Atau restart HP

### Jika ADA LOG tapi TIDAK ADA WARNING:
**Problem:** Detection logic salah atau threshold terlalu tinggi
**Check:** 
```bash
adb logcat -d | grep "AnalysisPipeline\|DefaultRuleProvider"
```

### Jika WARNING muncul untuk URL lain tapi tidak untuk ini:
**Problem:** URL sudah masuk whitelist (HITL)
**Check:**
```bash
adb logcat -d | grep "HITL Whitelist bypass"
```

## Known Issue

**Chrome ViewId mungkin berubah.**

Code mencari ViewId: `url_bar`, `url_bar_0`, `location_bar_status_icon_view`

Jika Chrome update dan ViewId berubah, service tidak bisa capture URL.

**Workaround:** Test dengan browser lain (Samsung Internet, Firefox, Brave)

## Conclusion

Service sudah running dan siap. Tinggal test manual:
1. Buka Chrome
2. Ketik bank-bca.vercell.app
3. Tunggu 5 detik
4. Warning popup HARUS muncul

Jika tidak muncul, kirim logcat output untuk debugging.

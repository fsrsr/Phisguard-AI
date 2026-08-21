# Panduan Setup Firestore Database - PhishGuard AI

## Step-by-Step: 2 Menit

---

## 1. Buka Firestore Console

**URL:** https://console.firebase.google.com/project/phishguard-73c60/firestore

Atau:
1. Buka https://console.firebase.google.com/
2. Pilih project "phishguard-73c60"
3. Sidebar kiri → "Firestore Database"

---

## 2. Klik "Create Database"

Tombol biru/putih dengan text "Create database"

---

## 3. Pilih Mode

**Ada 2 pilihan:**

### Opsi A: Test Mode (Recommended untuk Development)
- ✅ **Pilih ini untuk testing**
- Rules: Anyone can read/write for 30 days
- Perfect untuk development & testing
- Setelah 30 hari, rules otomatis lock (perlu update manual)

### Opsi B: Production Mode
- Rules: Deny all by default
- Harus setup security rules manual (lebih ribet)
- Untuk production deployment

**Rekomendasi: Pilih "Start in test mode"**

Klik **"Next"**

---

## 4. Pilih Location

**Pilih salah satu:**

- **asia-southeast1 (Singapore)** ← Recommended (lebih dekat, lebih cepat)
- **asia-southeast2 (Jakarta)**
- **asia-northeast1 (Tokyo)**
- **asia-south1 (Mumbai)**

**Warning:** Location tidak bisa diganti setelah dibuat!

**Rekomendasi: asia-southeast1 (Singapore)**

Klik **"Enable"**

---

## 5. Tunggu Database Creation

Progress bar muncul, tunggu 30-60 detik.

Status akan berubah jadi:
- "Cloud Firestore is being set up..."
- "Cloud Firestore is ready!"

---

## 6. Selesai! ✅

Anda akan melihat:
- Empty Firestore console
- Tab: Data, Rules, Indexes, Usage

Database sudah aktif dan siap dipakai!

---

## 7. (Opsional) Setup Security Rules untuk Production

**Jika nanti mau deploy ke production:**

1. Klik tab **"Rules"**
2. Replace rules dengan ini:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    
    // Phishing URLs collection
    match /phishing_urls/{urlId} {
      allow read: if true;  // Public read untuk semua app
      allow write: if request.auth != null;  // Write hanya authenticated users
    }
    
    // User reports collection
    match /user_reports/{reportId} {
      allow read: if request.auth != null;  // Read hanya authenticated users
      allow write: if true;  // Allow anonymous reports
    }
    
    // Detection logs (optional)
    match /detection_logs/{logId} {
      allow read, write: if request.auth != null;
    }
  }
}
```

3. Klik **"Publish"**

---

## 8. Verify di App

Setelah Firestore created, app akan otomatis connect.

**Test di HP:**
1. Buka app PhishGuard
2. Trigger detection (send phishing SMS, atau buka phishing URL)
3. Check logcat:
   ```bash
   adb logcat | grep -i firestore
   ```

Expected output:
```
FirebaseSyncManager: Syncing to Firestore...
FirebaseSyncManager: Sync complete
```

---

## Troubleshooting

### Jika error "Permission denied"
- Pastikan rules allow write untuk anonymous users
- Atau enable Authentication dulu

### Jika tidak ada data yang masuk
- Check internet connection di HP
- Check logcat untuk error messages
- Verify google-services.json sudah real (not placeholder)

### Jika build error setelah enable Firestore
- Rebuild: `./gradlew clean assembleDebug`
- Reinstall APK

---

## Quick Summary

1. Open: https://console.firebase.google.com/project/phishguard-73c60/firestore
2. Click: "Create database"
3. Choose: "Test mode"
4. Location: "asia-southeast1 (Singapore)"
5. Click: "Enable"
6. Wait: 30-60 seconds
7. Done! ✅

---

**Estimated Time:** 2 minutes  
**Difficulty:** Easy  
**Required:** Internet connection  

Setelah selesai, cloud sync akan otomatis aktif di app!

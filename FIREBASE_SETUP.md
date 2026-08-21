# Firebase Setup - Project: PhishGuard

## Your Firebase Project Info
- **Project Name:** PhishGuard
- **Project Number:** 367066463268
- **Project ID:** phishguard
- **Console URL:** https://console.firebase.google.com/project/phishguard

---

## Quick Setup Steps

### 1. Register Android App in Firebase

**Go to:**
```
https://console.firebase.google.com/project/phishguard/settings/general
```

**Steps:**
1. Scroll to "Your apps" section
2. Click "+ Add app" button
3. Select **Android** (robot icon)
4. Enter:
   - **Android package name:** `com.example.ai_project_singapore`
   - **App nickname (optional):** PhishGuard AI
   - **Debug signing certificate SHA-1 (optional):** Skip for now
5. Click **"Register app"**
6. **Download google-services.json** ← IMPORTANT
7. Keep this file, you'll need it in step 4

### 2. Enable Email/Password Authentication

**Go to:**
```
https://console.firebase.google.com/project/phishguard/authentication/providers
```

**Steps:**
1. If first time: Click **"Get started"**
2. Go to **"Sign-in method"** tab
3. Click **"Email/Password"** row
4. Toggle **"Enable"** switch ON
5. Click **"Save"**

### 3. Create Firestore Database

**Go to:**
```
https://console.firebase.google.com/project/phishguard/firestore
```

**Steps:**
1. Click **"Create database"**
2. Select **"Start in test mode"** (recommended for development)
   - Rules: Anyone can read/write for 30 days
   - Perfect for testing
3. Choose location: **asia-southeast1 (Singapore)** or **asia-southeast2 (Jakarta)**
4. Click **"Enable"**
5. Wait 30-60 seconds for database creation

**Optional - Add Security Rules (for production later):**

Click "Rules" tab and paste:
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /phishing_urls/{urlId} {
      allow read: if true;
      allow write: if request.auth != null;
    }
    match /user_reports/{reportId} {
      allow read: if request.auth != null;
      allow write: if true;
    }
  }
}
```

### 4. Replace google-services.json & Rebuild

**After downloading real google-services.json from step 1:**

```bash
# Copy the real file to project
cp ~/Downloads/google-services.json /home/sn0wden/Documents/AI-Ready-ASEAN-Youth-MVP/app/

# Verify it's not placeholder
cat /home/sn0wden/Documents/AI-Ready-ASEAN-Youth-MVP/app/google-services.json | grep PLACEHOLDER
# Should return nothing if file is real

# Rebuild APK
cd /home/sn0wden/Documents/AI-Ready-ASEAN-Youth-MVP
export ANDROID_HOME=~/Android/Sdk
./gradlew assembleDebug

# Install to device
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## Current Status

### ✓ Done
- Project identified: PhishGuard (367066463268)
- google-services.json updated with correct project_id: `phishguard`
- Package name configured: `com.example.ai_project_singapore`

### ⚠️ Needs Manual Action
- [ ] Register Android app in Firebase Console → get real App ID
- [ ] Enable Email/Password Authentication
- [ ] Create Firestore Database
- [ ] Download real google-services.json
- [ ] Replace file & rebuild APK

### 📄 Current google-services.json
**Status:** PARTIAL - project_id correct, but App ID and API Key still placeholder

```json
{
  "project_id": "phishguard", ✓
  "project_number": "367066463268", ✓
  "mobilesdk_app_id": "1:367066463268:android:PLACEHOLDER_APP_ID", ❌
  "current_key": "PLACEHOLDER_API_KEY" ❌
}
```

---

## Verification After Setup

After completing all steps, verify Firebase connection:

```bash
# Launch app
adb shell am start -n com.example.ai_project_singapore/.MainActivity

# Check logs for Firebase connection
adb logcat -d | grep -i "firebase\|firestore"
```

Expected output:
```
FirebaseApp: Successfully configured Firebase
FirebaseSyncManager: Firebase sync selesai
```

If you see errors, check:
1. google-services.json has real values (no PLACEHOLDER)
2. Package name matches exactly: `com.example.ai_project_singapore`
3. Firestore database created in Firebase Console

---

## Estimated Time
- Step 1 (Register app): 2 minutes
- Step 2 (Enable auth): 1 minute
- Step 3 (Create Firestore): 2 minutes
- Step 4 (Replace & rebuild): 2 minutes

**Total: ~7 minutes**

---

## Need Help?

If you encounter errors during setup, share:
1. Screenshot of error from Firebase Console
2. Or logcat output: `adb logcat -d | grep -i firebase`

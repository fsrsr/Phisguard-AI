# Firebase Setup Instructions - Manual

## Your Firebase Project
- Project Number: **367066463268**
- Authentication: Email/Password (needs to be enabled)
- Database: Firestore (needs to be created)

## Steps to Complete Setup

### 1. Open Firebase Console
```
https://console.firebase.google.com/project/367066463268
```

If you don't have access, you need to:
1. Go to https://console.firebase.google.com/
2. Find your project with ID: 367066463268
3. Or share the project name so I can help further

### 2. Register Android App

1. In Firebase Console → Project Settings (gear icon)
2. Scroll down → "Your apps" section
3. Click "Add app" → Select Android (robot icon)
4. Fill in:
   ```
   Android package name: com.example.ai_project_singapore
   App nickname: PhishGuard AI
   Debug SHA-1: (optional, skip for now)
   ```
5. Click "Register app"
6. **Download google-services.json**
7. Replace the file at: `/home/sn0wden/Documents/AI-Ready-ASEAN-Youth-MVP/app/google-services.json`

### 3. Enable Email/Password Authentication

1. Firebase Console → Authentication
2. Click "Get started" (if first time)
3. Go to "Sign-in method" tab
4. Click "Email/Password"
5. Toggle "Enable"
6. Click "Save"

### 4. Create Firestore Database

1. Firebase Console → Firestore Database
2. Click "Create database"
3. Select mode:
   - **Test mode** (for development - rules open for 30 days)
   - Or **Production mode** (secure, but needs rules setup)
4. Choose location: `asia-southeast1` (Singapore) or `asia-southeast2` (Jakarta)
5. Click "Enable"

### 5. (Optional) Setup Firestore Security Rules

If you chose Production mode, add these rules:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Phishing URLs - public read, auth write
    match /phishing_urls/{urlId} {
      allow read: if true;
      allow write: if request.auth != null;
    }
    
    // User reports - allow anonymous reports
    match /user_reports/{reportId} {
      allow read: if request.auth != null;
      allow write: if true;
    }
  }
}
```

### 6. After Getting Real google-services.json

Copy the real file to project:
```bash
cp ~/Downloads/google-services.json /home/sn0wden/Documents/AI-Ready-ASEAN-Youth-MVP/app/
```

Then rebuild APK:
```bash
cd /home/sn0wden/Documents/AI-Ready-ASEAN-Youth-MVP
export ANDROID_HOME=~/Android/Sdk
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Current Status

⚠️ **google-services.json is still PLACEHOLDER**

The file currently has:
- Project Number: 367066463268 ✓ (correct)
- Project ID: PLACEHOLDER_PROJECT_ID ❌ (needs real value)
- App ID: PLACEHOLDER_APP_ID ❌ (from step 2)
- API Key: PLACEHOLDER_API_KEY ❌ (from step 2)

Without real values, Firebase features will not work:
- ❌ Firestore sync
- ❌ Authentication
- ❌ Analytics

## Alternative: Provide Access

If you can share:
1. Project name (not just number)
2. Or add my Google account to project as Editor
3. Or share the real google-services.json content

Then I can complete the setup automatically.

# Cadangan aturan Firestore sebelum pengetatan

Ruleset `093228a4-9166-41b4-ac87-5ac680388816`, aktif 2026-08-02 s/d 2026-08-20.
Disimpan agar pengetatan bisa dibatalkan kalau ada fitur yang ternyata patah.

```
    rules_version = '2';
    service cloud.firestore {
      match /databases/{database}/documents {
        
        // Allow all read/write untuk development
        match /{document=**} {
          allow read, write: if true;
        }
      }
    }
```

Kembalikan dengan menempelkan isi di atas ke `firestore.rules` lalu:
```bash
npx -y firebase-tools@latest deploy --only firestore:rules --project phishguard-73c60
```

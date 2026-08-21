# Bukti: akun Defen21 dikembalikan 404 ke publik

Dikumpulkan 21 Agustus 2026. Dipakai sebagai lampiran banding ke GitHub Support.

## Gejala

Repositori diset publik, tapi pengunjung yang tidak login mendapat 404.
Bukan satu repo — seluruh akun tidak terlihat.

## Pengukuran

| Pemeriksaan | Terautentikasi (pemilik) | Anonim |
|---|---|---|
| `repos/Defen21/PHISHGUARD` | `private: false`, `visibility: public` | **HTTP 404** |
| `github.com/Defen21/PHISHGUARD` | normal | **HTTP 404** |
| `github.com/Defen21` (profil) | normal | **HTTP 404** |
| `users/Defen21/repos` | 14 repo publik | **0 terlihat** |

## Kemungkinan lain yang sudah disingkirkan

- **Bukan rate limit.** Kuota anonim 57/60 tersisa; rate limit juga
  mengembalikan 403, bukan 404.
- **Bukan setelan repo.** API terautentikasi melaporkan `private: false`.
- **Bukan gangguan GitHub.** Akun pembanding normal pada saat yang sama:
  `users/torvalds` → 200, `users/Ov3rkill15` → 200.
- **Bukan salah URL.** URL yang sama berhasil saat diakses dengan
  autentikasi pemilik.

## Perintah untuk mereproduksi

```bash
curl -s -o /dev/null -w "%{http_code}\n" https://api.github.com/users/Defen21
curl -s -o /dev/null -w "%{http_code}\n" https://api.github.com/users/torvalds
curl -s "https://api.github.com/users/Defen21/repos" | jq length
```

## Konteks isi repositori

Repositori utama berisi **PhishGuard**, aplikasi Android anti-penipuan untuk
pengguna Indonesia. Isinya memuat:

- `app/src/main/assets/blocklist.bloom` — Bloom filter 9,4 MB berisi 4,1 juta
  domain phishing, malware, dan judi online, dibangun dari blocklist publik
  [Lyra (ITSEC Research)](https://github.com/ITSEC-Research/Lyra)
- `tools/build_blocklist.py` — skrip yang membangun aset tersebut
- Daftar kata penanda situs judi dan pola pesan penipuan

Seluruh data itu dipakai untuk **memblokir** situs berbahaya demi melindungi
pengguna, bukan untuk menyebarkannya. Bila penandaan otomatis dipicu oleh
keberadaan daftar domain berbahaya ini, mohon ditinjau ulang dengan konteks
tersebut.

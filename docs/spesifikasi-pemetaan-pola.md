# Referensi Integrasi: Pemetaan Pola Kejahatan (Crime Pattern Mapping)

## 1. Konteks dan Tujuan (Context & Objective)
Dokumen ini berfungsi sebagai referensi bagi AI Agent untuk mengintegrasikan hasil analisis pola kejahatan ke dalam sistem. Tujuannya adalah memvisualisasikan data kejahatan sehingga pengguna dapat melihat *hotspot* (titik rawan), tren waktu, dan korelasi spasial berdasarkan data historis.

## 2. Pola Kejahatan yang Telah Dianalisis (Analyzed Patterns)
AI Agent harus merancang sistem pemetaan untuk mengakomodasi 3 dimensi pola berikut:

### A. Pola Spasial (Geographical Hotspots)
*   **Karakteristik:** Kejahatan menumpuk pada area tertentu dengan radius berdekatan.
*   **Metode Pemetaan:** `Heatmap` atau `Clustering` (misal: algoritma K-Means atau DBSCAN untuk pengelompokan titik koordinat).
*   **Visualisasi:** Area dengan intensitas tinggi diberi gradasi warna merah/gelap, sedangkan area rendah berwarna hijau/terang.

### B. Pola Temporal (Time-based Trends)
*   **Karakteristik:** Fluktuasi tingkat kejahatan berdasarkan waktu (Pagi, Siang, Malam) atau hari (Hari Kerja vs Akhir Pekan).
*   **Implementasi Sistem:** Tambahkan *filter/slider* waktu pada antarmuka peta agar pengguna bisa melihat perubahan *hotspot* dari jam ke jam.
*   **Korelasi:** Misalnya, kejahatan jalanan (begal/jambret) lebih tinggi pada pukul 22:00 - 04:00.

### C. Pola Kategorikal (Crime Typology)
*   **Karakteristik:** Jenis kejahatan tertentu terjadi di lokasi spesifik (contoh: pencurian kendaraan di area perumahan/kampus, pencopetan di pusat keramaian/pasar).
*   **Visualisasi:** Gunakan *Custom Markers* atau *Icons* pada peta berdasarkan kategori tindak pidana.

## 3. Instruksi Eksekusi untuk AI Agent (Implementation Directives)

Tolong integrasikan fitur pemetaan ini dengan mengikuti langkah-langkah teknis berikut:

1.  **Persiapan Data (Data Preparation):**
    *   Pastikan tabel database (SQL/NoSQL) memiliki field wajib: `latitude`, `longitude`, `timestamp`, `crime_type`, dan `severity_level`.
    *   Buat *endpoint* API (misalnya menggunakan Golang/Node.js) yang mengembalikan data spasial dalam format **GeoJSON** untuk mempermudah rendering di sisi *frontend*.

2.  **Pemilihan Library Visualisasi (Frontend):**
    *   Jika menggunakan React/Next.js: Gunakan library seperti `react-leaflet`, `mapbox-gl-js`, atau `deck.gl` untuk performa *rendering* data dalam jumlah besar.
    *   Terapkan fitur `MarkerClusterGroup` agar peta tidak *lag* ketika menampilkan ribuan titik insiden sekaligus.

3.  **Logika Filter & Interaksi (Filtering Logic):**
    *   Implementasikan *state management* untuk memfilter peta berdasarkan rentang tanggal (Date Range Picker).
    *   Tambahkan *checkbox* kategori kejahatan untuk menyembunyikan/menampilkan marker tertentu.

## 4. Struktur Data (Expected Payload Schema)
AI Agent harus memastikan API merespons dengan struktur seperti ini saat mengirim data ke klien:

```json
{
  "type": "FeatureCollection",
  "features": [
    {
      "type": "Feature",
      "geometry": {
        "type": "Point",
        "coordinates": [107.6191, -6.9175] 
      },
      "properties": {
        "id": "CR-10293",
        "type": "Pencurian Kendaraan",
        "time_of_occurrence": "2026-08-25T23:30:00Z",
        "risk_weight": 0.8
      }
    }
  ]
}
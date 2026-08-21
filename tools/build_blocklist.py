#!/usr/bin/env python3
"""
Bangun aset deteksi PhishGuard dari blocklist Lyra (ITSEC Research).

    https://github.com/ITSEC-Research/Lyra

Lyra BUKAN dataset training model — isinya daftar domain teks polos per
kategori, diperbarui harian. Jadi yang dilakukan di sini bukan melatih
jaringan saraf, melainkan dua hal yang memang bisa dilakukan pada data
seperti ini:

  1. MENGEMAS jutaan domain jadi Bloom filter kecil yang muat di APK,
     supaya aplikasi bisa memeriksa domain secara luring dalam O(1).
  2. MENGKALIBRASI aturan heuristik dari data: TLD mana yang benar-benar
     disalahgunakan, dan kata apa yang benar-benar menandai situs judi.
     Angka-angka di UrlRiskScorer/JudolWordlist sebelumnya hasil tebakan.

Referensi domain SAH (Tranco top 1M) dipakai sebagai pembanding. Tanpa itu
".com" akan tampak paling jahat hanya karena paling banyak — yang justru
melahirkan false positive.

Pakai:
    python3 tools/build_blocklist.py --lyra /path/ke/Lyra [--tranco tranco.zip]

Keluaran:
    app/src/main/assets/blocklist.bloom   (aset yang dibaca aplikasi)
    tools/blocklist_report.md             (hasil kalibrasi untuk ditinjau)
"""

import argparse
import hashlib
import io
import json
import math
import os
import re
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone

# Kategori yang diikutkan ke Bloom filter. "adult" dan "ads" sengaja
# ditinggal: aplikasi ini soal penipuan, bukan penyaring konten, dan
# keduanya akan menggandakan ukuran aset tanpa menambah perlindungan.
BLOOM_CATEGORIES = ["suspicious", "malicious", "gambling"]

# Kategori yang domain populernya disaring keluar. Lihat penjelasan panjang
# di main() — intinya gambling tidak boleh ikut disaring begitu saja.
EXCLUDE_POPULAR_FROM = {"suspicious", "malicious"}

# Untuk kategori gambling, domain populer dipertahankan HANYA bila namanya
# sendiri mengandung jargon judi. Ini memisahkan bandar besar yang memang
# harus diblokir (bet365, sportybet, 1xbet) dari situs populer yang tersapu
# umpan terlalu longgar (dribbble.com, mundodeportivo.com).
GAMBLING_MARKERS = (
    "bet", "casino", "kasino", "slot", "togel", "toto", "lottery", "lotto",
    "poker", "judi", "gacor", "bandar", "jackpot", "spin", "wager", "odds",
    "1win", "bingo", "baccarat", "roulette", "gambl", "taruhan",
)


def looks_like_gambling(domain):
    name = domain.rsplit(".", 1)[0]
    return any(marker in name for marker in GAMBLING_MARKERS)

# Target false-positive Bloom filter. 0,01% dipilih supaya pada pemakaian
# ~100 domain/hari, satu salah-blokir terjadi sekitar sekali per 3 tahun.
TARGET_FPR = 0.0001

MAGIC = b"PGBL"
FORMAT_VERSION = 1

HEADER_RE = re.compile(r"^\s*$|^/\*\*|^Lyra|^Category:|^Website:|^Copyright|^\*\*$")
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-._]*[a-z0-9])?$")


# ── Pemuatan data ───────────────────────────────────────────────────────

def load_list(path):
    """Baca satu file blocklist Lyra jadi himpunan domain bersih."""
    out = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip().lower()
            if not line or HEADER_RE.match(line):
                continue
            # Beberapa sumber memakai gaya adblock (||domain^) atau wildcard.
            line = line.lstrip("*.").lstrip("|").rstrip("^")
            if line.startswith("#"):
                continue
            if "." not in line or not DOMAIN_RE.match(line):
                continue
            out.add(line)
    return out


def load_tranco(path):
    """Daftar domain populer sebagai acuan 'sah'."""
    if not path or not os.path.exists(path):
        return []
    raw = (
        zipfile.ZipFile(path).open(zipfile.ZipFile(path).namelist()[0]).read()
        if path.endswith(".zip")
        else open(path, "rb").read()
    )
    ranked = []
    for line in io.BytesIO(raw).read().decode("utf-8", "ignore").splitlines():
        parts = line.split(",")
        if len(parts) == 2:
            ranked.append(parts[1].strip().lower())
    return ranked


# ── Bloom filter ────────────────────────────────────────────────────────

def bloom_params(n, fpr):
    m = int(math.ceil(-n * math.log(fpr) / (math.log(2) ** 2)))
    m += (8 - m % 8) % 8                       # bulatkan ke byte penuh
    k = max(1, int(round((m / n) * math.log(2))))
    return m, k


def bloom_indices(domain, m, k):
    """
    Double hashing dari satu SHA-256. Sengaja pakai SHA-256, bukan hash
    cepat buatan sendiri, supaya Python dan Kotlin dijamin menghasilkan
    indeks yang sama persis tanpa perlu menyalin implementasi hash.
    """
    d = hashlib.sha256(domain.encode("utf-8")).digest()
    h1 = int.from_bytes(d[0:8], "big")
    h2 = int.from_bytes(d[8:16], "big")
    for i in range(k):
        yield ((h1 + i * h2) & 0xFFFFFFFFFFFFFFFF) % m


def build_bloom(domains, fpr):
    n = len(domains)
    m, k = bloom_params(n, fpr)
    bits = bytearray(m // 8)
    for dom in domains:
        for idx in bloom_indices(dom, m, k):
            bits[idx >> 3] |= 1 << (idx & 7)
    return bits, m, k, n


def write_bloom(path, bits, m, k, n):
    with open(path, "wb") as fh:
        fh.write(MAGIC)
        fh.write(FORMAT_VERSION.to_bytes(4, "big"))
        fh.write(m.to_bytes(8, "big"))
        fh.write(k.to_bytes(4, "big"))
        fh.write(n.to_bytes(8, "big"))
        fh.write(bits)


# ── Kalibrasi: TLD mana yang benar-benar disalahgunakan ────────────────

def tld_of(domain):
    return domain.rsplit(".", 1)[-1]


def calibrate_tlds(bad_domains, benign_domains, min_bad=500, min_lift=8.0):
    """
    Bandingkan pangsa tiap TLD di daftar jahat vs di daftar populer.
    Rasio (lift) tinggi = TLD itu memang sarang, bukan sekadar besar.
    """
    bad = Counter(tld_of(d) for d in bad_domains)
    good = Counter(tld_of(d) for d in benign_domains)
    total_bad, total_good = sum(bad.values()), max(1, sum(good.values()))

    rows = []
    for tld, cnt in bad.items():
        if cnt < min_bad:
            continue
        share_bad = cnt / total_bad
        # +1 smoothing: TLD yang tak pernah muncul di daftar sah tidak
        # boleh menghasilkan pembagian nol / lift tak hingga.
        share_good = (good.get(tld, 0) + 1) / total_good
        rows.append((tld, cnt, good.get(tld, 0), share_bad / share_good))

    rows.sort(key=lambda r: -r[3])
    return rows, [r[0] for r in rows if r[3] >= min_lift]


# ── Kalibrasi: kata penanda judi ───────────────────────────────────────

TOKEN_RE = re.compile(r"[a-z]{3,}")


def tokens_of(domain):
    host = domain.rsplit(".", 1)[0]          # buang TLD
    return set(TOKEN_RE.findall(host))


def calibrate_gambling_terms(gambling, contrast, benign, top=60, min_count=800):
    """
    Kata yang sering muncul di domain judi TAPI jarang di kategori lain
    dan di daftar situs populer. Kontras inilah yang menyaring kata umum
    seperti "online" atau "web" yang muncul di mana-mana.
    """
    g = Counter()
    for d in gambling:
        g.update(tokens_of(d))
    c = Counter()
    for d in contrast:
        c.update(tokens_of(d))
    b = Counter()
    for d in benign:
        b.update(tokens_of(d))

    tot_g, tot_c, tot_b = sum(g.values()), max(1, sum(c.values())), max(1, sum(b.values()))

    rows = []
    for term, cnt in g.items():
        if cnt < min_count:
            continue
        share_g = cnt / tot_g
        share_other = ((c.get(term, 0) / tot_c) + (b.get(term, 0) / tot_b)) / 2
        lift = share_g / (share_other + 1e-9)
        rows.append((term, cnt, c.get(term, 0), b.get(term, 0), lift))

    rows.sort(key=lambda r: -r[4])
    return rows[:top]


# ── Main ────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lyra", required=True, help="path ke checkout repo Lyra")
    ap.add_argument("--tranco", default="", help="tranco top-1m.csv.zip (acuan domain sah)")
    ap.add_argument("--out", default="app/src/main/assets/blocklist.bloom")
    ap.add_argument("--report", default="tools/blocklist_report.md")
    ap.add_argument("--fpr", type=float, default=TARGET_FPR)
    ap.add_argument("--exclude-top", type=int, default=50000,
                    help="kecualikan N situs paling populer dari kategori "
                         "suspicious/malicious (lihat EXCLUDE_POPULAR_FROM)")
    args = ap.parse_args()

    cats = {}
    for name in BLOOM_CATEGORIES + ["adult", "ads"]:
        path = os.path.join(args.lyra, "blocklist", f"{name}.txt")
        if os.path.exists(path):
            cats[name] = load_list(path)
            print(f"  {name:12s} {len(cats[name]):>9,} domain", file=sys.stderr)

    benign_ranked = load_tranco(args.tranco)
    benign = set(benign_ranked)
    top_excluded = set(benign_ranked[: args.exclude_top])
    print(f"  tranco       {len(benign):>9,} domain acuan", file=sys.stderr)

    # ── Bloom filter ────────────────────────────────────────────────
    # Penyaringan situs populer HANYA untuk suspicious/malicious. Kedua
    # kategori itu menggabungkan umpan adtech/hosting, sehingga domain
    # populer yang masuk ke sana (1rtb.com, 000webhost.com, 3322.net)
    # hampir selalu derau — sementara domain phishing sungguhan tidak
    # pernah sampai peringkat setinggi itu.
    #
    # Kategori gambling SENGAJA tidak disaring: 1xbet.com dan 1win.com ada
    # di peringkat teratas justru karena besar, dan memblokirnya memang
    # tujuan aplikasi ini. Popularitas bukan bukti keabsahan untuk judi.
    union = set()
    removed = {}
    for name in BLOOM_CATEGORIES:
        domains = cats.get(name, set())
        if name in EXCLUDE_POPULAR_FROM:
            hit = domains & top_excluded
            removed[name] = len(hit)
            domains = domains - top_excluded
        elif name == "gambling":
            drop = {d for d in domains & top_excluded if not looks_like_gambling(d)}
            removed[name] = len(drop)
            domains = domains - drop
        union |= domains
    overlap_top = union & top_excluded

    bits, m, k, n = build_bloom(union, args.fpr)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    write_bloom(args.out, bits, m, k, n)
    size_mb = (len(bits) + 24) / 1024 / 1024
    print(f"  bloom        {n:,} domain → {size_mb:.1f} MB (m={m}, k={k})", file=sys.stderr)

    # ── Kalibrasi ───────────────────────────────────────────────────
    tld_rows, cheap_tlds = calibrate_tlds(union, benign) if benign else ([], [])
    gambling_rows = (
        calibrate_gambling_terms(
            cats.get("gambling", set()),
            cats.get("suspicious", set()) | cats.get("malicious", set()),
            benign,
        )
        if cats.get("gambling")
        else []
    )

    # ── Laporan ─────────────────────────────────────────────────────
    with open(args.report, "w", encoding="utf-8") as fh:
        w = fh.write
        w("# Laporan kalibrasi blocklist\n\n")
        w(f"Dibuat: {datetime.now(timezone.utc).isoformat()}\n\n")
        w("Sumber: [Lyra — ITSEC Research](https://github.com/ITSEC-Research/Lyra), ")
        w("acuan domain sah: Tranco top 1M.\n\n")

        w("## Bloom filter\n\n")
        w(f"- Kategori: {', '.join(BLOOM_CATEGORIES)}\n")
        for name in BLOOM_CATEGORIES:
            w(f"  - {name}: {len(cats.get(name, set())):,}\n")
        w(f"- Domain unik setelah gabung: {n:,}\n")
        w(f"- Disaring dari {'/'.join(sorted(EXCLUDE_POPULAR_FROM))} "
          f"(top {args.exclude_top:,} Tranco): ")
        w(", ".join(f"{kategori} −{jml:,}" for kategori, jml in sorted(removed.items())))
        w("\n")
        w(f"- Domain populer yang tetap masuk (dari gambling, disengaja): "
          f"{len(overlap_top):,}")
        if overlap_top:
            w(f" — {', '.join(sorted(overlap_top)[:8])}")
        w("\n")
        w(f"- Ukuran aset: {size_mb:.1f} MB (m={m:,} bit, k={k})\n")
        w(f"- Target false positive: {args.fpr:.4%}\n\n")

        if tld_rows:
            w("## TLD paling disalahgunakan\n\n")
            w("Lift = pangsa di daftar jahat ÷ pangsa di daftar situs populer. ")
            w("Lift tinggi berarti TLD itu memang sarang, bukan sekadar populer.\n\n")
            w("| TLD | jahat | populer | lift |\n|---|---:|---:|---:|\n")
            for tld, bad_c, good_c, lift in tld_rows[:40]:
                w(f"| .{tld} | {bad_c:,} | {good_c:,} | {lift:,.0f}× |\n")
            w("\n### Usulan CHEAP_TLDS\n\n```kotlin\n")
            w(",\n".join(
                "        " + ", ".join(f'"{t}"' for t in cheap_tlds[i:i + 8])
                for i in range(0, len(cheap_tlds), 8)
            ))
            w("\n```\n\n")

        if gambling_rows:
            w("## Kata penanda judi (kontras vs kategori lain + situs populer)\n\n")
            w("| kata | di judi | di kategori lain | di populer | lift |\n")
            w("|---|---:|---:|---:|---:|\n")
            for term, gc, cc, bc, lift in gambling_rows:
                w(f"| {term} | {gc:,} | {cc:,} | {bc:,} | {lift:,.0f}× |\n")

    print(f"\nLaporan: {args.report}", file=sys.stderr)

    json.dump(
        {"domains": n, "bits": m, "hashes": k, "size_bytes": len(bits) + 24,
         "categories": {c: len(cats.get(c, set())) for c in BLOOM_CATEGORIES},
         "target_fpr": args.fpr},
        open(args.report.replace(".md", ".json"), "w"),
        indent=2,
    )


if __name__ == "__main__":
    main()

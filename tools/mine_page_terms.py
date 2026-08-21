#!/usr/bin/env python3
"""
Kalibrasi kata penanda judi dari ISI HALAMAN, bukan dari nama domain.

LATAR BELAKANG
JudolWordlist saat ini dikalibrasi dari 1,8 juta nama domain (lihat
build_blocklist.py). Itu bagus untuk menebak domain, tapi sinyal
"pageText" di UrlRiskScorer menilai TEKS HALAMAN — dan kosakata di badan
halaman berbeda dari kosakata di nama domain. Skrip ini menutup lubang itu.

METODE
Dua korpus diambil berdampingan:
  1. judol  — beranda domain dari kategori gambling Lyra
  2. sah    — beranda domain Indonesia populer dari Tranco (.id/.co.id/…)

Lalu dihitung DOCUMENT FREQUENCY tiap kata di kedua korpus, dan lift-nya.
Korpus pembanding itu wajib: tanpa itu "daftar", "situs", "login", "klik"
akan tampak sebagai penanda judi padahal cuma kata Indonesia biasa —
persis kekeliruan yang hampir terjadi pada kalibrasi berbasis domain.

Document frequency, bukan jumlah kemunculan: satu halaman yang mengulang
"slot" 400 kali tidak boleh menggeser statistik seluruh korpus.

KEAMANAN
Pengambilan memakai HTTP polos — JavaScript situs TIDAK dieksekusi, jadi
tidak ada permukaan serangan browser. Ukuran respons dibatasi, hanya
beranda yang diambil (satu permintaan per domain), dan hasil unduhan
diperlakukan murni sebagai teks.

Pakai:
    python3 tools/mine_page_terms.py --lyra /path/Lyra --tranco top-1m.csv.zip
"""

import argparse
import io
import json
import os
import random
import re
import sys
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests
from lxml import html as lxml_html

HEADER_RE = re.compile(r"^\s*$|^/\*\*|^Lyra|^Category:|^Website:|^Copyright|^\*\*$")
TOKEN_RE = re.compile(r"[a-z]{3,20}")
MAX_BYTES = 400_000
TIMEOUT = 8

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"

# Kata yang tidak boleh jadi penanda apa pun: kata fungsi Indonesia/Inggris
# dan istilah web generik. Disaring lebih dulu supaya laporan tidak penuh derau.
STOPWORDS = set("""
yang dan atau dengan untuk dari pada dalam adalah akan tidak bisa dapat
ini itu ada juga oleh sebagai telah sudah lebih agar bila jika karena
serta saat kami kita anda mereka saya semua setiap hanya masih harus
the and for you are with from that this have has был not all can will
your our their its out about more when what who how why where
home about contact privacy policy terms service copyright rights reserved
login logout register account user password email search menu next prev
page site web www http https html index new view read click here link
january february march april may june july august september october
november december senin selasa rabu kamis jumat sabtu minggu
""".split())


# ── Pemuatan daftar domain ──────────────────────────────────────────────

def load_lyra(path):
    out = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip().lower()
            if not line or HEADER_RE.match(line) or "." not in line:
                continue
            out.append(line)
    return out


def load_tranco_id(path, limit=6000):
    z = zipfile.ZipFile(path)
    raw = z.open(z.namelist()[0]).read().decode("utf-8", "ignore")
    out = []
    for line in raw.splitlines():
        parts = line.split(",")
        if len(parts) != 2:
            continue
        d = parts[1].strip().lower()
        if d.endswith(".id") or ".co.id" in d or ".ac.id" in d or ".go.id" in d:
            out.append(d)
        if len(out) >= limit:
            break
    return out


# ── Pengambilan halaman ─────────────────────────────────────────────────

# Penanda halaman yang BUKAN isi situs sebenarnya. Ini wajib: di jaringan
# Indonesia mayoritas domain judi dibajak DNS-nya ke halaman "Internet
# Positif", dan tanpa saringan ini korpusnya akan berisi kosakata halaman
# blokir ("blocked", "administrator", "accordance") alih-alih kosakata judi.
BLOCKPAGE_MARKERS = (
    "internet positif", "internetpositif", "trustpositif", "trust+ positif",
    "web page blocked", "halaman diblokir", "situs ini diblokir",
    "kominfo", "komdigi", "kemkominfo", "aduankonten",
    "diblokir oleh", "akses diblokir", "blokir internet sehat",
    "if you believe this is an error", "contact your administrator",
    "in accordance with the",
    # Halaman tantangan WAF/Cloudflare. Ditemukan setelah putaran pertama:
    # ~39% halaman yang lolos blokir ISP ternyata halaman WAF, sehingga
    # "malformed", "phrase", "sql", "triggered" ikut terhitung sebagai
    # kosakata judi. Inilah bagian yang butuh browser anti-deteksi.
    "triggered the security solution", "sql command or malformed",
    "certain word or phrase", "cloudflare ray id", "attention required",
    "checking your browser before", "enable javascript and cookies",
    "access denied", "request blocked", "are you a robot",
    "ddos protection by", "performance & security by cloudflare",
)

# Halaman parkir / dijual — juga bukan isi situs.
PARKING_MARKERS = (
    "domain is for sale", "buy this domain", "domain parking",
    "this domain is parked", "domain may be for sale",
    "renew now to keep", "expired domain",
)


def classify_page(text):
    """'blokir', 'parkir', atau 'ok'."""
    low = text[:4000].lower()
    if any(m in low for m in BLOCKPAGE_MARKERS):
        return "blokir"
    if any(m in low for m in PARKING_MARKERS):
        return "parkir"
    return "ok"


def fetch_text(domain):
    """Ambil beranda, kembalikan teks tampak. None bila gagal/terblokir."""
    for scheme in ("https://", "http://"):
        try:
            r = requests.get(
                scheme + domain,
                timeout=TIMEOUT,
                headers={"User-Agent": UA, "Accept-Language": "id-ID,id;q=0.9,en;q=0.8"},
                allow_redirects=True,
                stream=True,
            )
            ctype = r.headers.get("content-type", "")
            if "html" not in ctype.lower():
                r.close()
                continue
            body = r.raw.read(MAX_BYTES, decode_content=True)
            r.close()
            if not body:
                continue
            status = r.status_code
            doc = lxml_html.fromstring(body)
            for bad in doc.xpath("//script|//style|//noscript"):
                bad.getparent().remove(bad)
            text = " ".join(doc.itertext())
            title = " ".join(doc.xpath("//title/text()") or [])
            clean = re.sub(r"\s+", " ", (title + " " + text)).strip()[:60_000]
            return {"domain": domain, "status": status,
                    "kind": classify_page(clean), "text": clean}
        except Exception:
            continue
    return None


def harvest(domains, workers, label):
    pages = []
    stats = Counter()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_text, d): d for d in domains}
        for i, fut in enumerate(as_completed(futures), 1):
            res = fut.result()
            if not res or len(res["text"]) < 200:
                stats["gagal"] += 1
            else:
                stats[res["kind"]] += 1
                if res["kind"] == "ok":
                    pages.append(res)
            if i % 1000 == 0:
                print(f"  [{label}] {i}/{len(domains)} — asli {len(pages)}, "
                      f"blokir {stats['blokir']}, parkir {stats['parkir']}, "
                      f"gagal {stats['gagal']}", file=sys.stderr)
    print(f"  [{label}] SELESAI: {len(pages)} halaman asli | "
          f"blokir {stats['blokir']} | parkir {stats['parkir']} | "
          f"gagal {stats['gagal']}", file=sys.stderr)
    return pages, stats


# ── Analisis ────────────────────────────────────────────────────────────

def doc_frequency(pages):
    """Berapa HALAMAN yang memuat tiap kata (bukan berapa kali muncul)."""
    df = Counter()
    for p in pages:
        for term in set(TOKEN_RE.findall(p["text"].lower())):
            if term not in STOPWORDS:
                df[term] += 1
    return df


def rank_terms(df_bad, n_bad, df_good, n_good, min_share=0.02, top=120):
    rows = []
    for term, cnt in df_bad.items():
        share_bad = cnt / max(1, n_bad)
        if share_bad < min_share:              # harus muncul di cukup banyak halaman
            continue
        # +1 smoothing supaya kata yang tak pernah muncul di korpus sah
        # tidak menghasilkan lift tak hingga.
        share_good = (df_good.get(term, 0) + 1) / max(1, n_good + 1)
        rows.append((term, cnt, df_good.get(term, 0), share_bad, share_good,
                     share_bad / share_good))
    rows.sort(key=lambda r: -r[5])
    return rows[:top]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lyra", required=True)
    ap.add_argument("--tranco", required=True)
    ap.add_argument("--judol-sample", type=int, default=4000)
    ap.add_argument("--benign-sample", type=int, default=2500)
    ap.add_argument("--workers", type=int, default=64)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--corpus-dir", default="")
    ap.add_argument("--report", default="tools/page_terms_report.md")
    args = ap.parse_args()

    random.seed(args.seed)

    gambling = load_lyra(os.path.join(args.lyra, "blocklist", "gambling.txt"))
    judol_sample = random.sample(gambling, min(args.judol_sample, len(gambling)))
    benign_all = load_tranco_id(args.tranco)
    benign_sample = benign_all[: args.benign_sample]

    print(f"Mengambil {len(judol_sample)} beranda judol dan "
          f"{len(benign_sample)} beranda Indonesia sah…", file=sys.stderr)

    judol_pages, judol_stats = harvest(judol_sample, args.workers, "judol")
    benign_pages, benign_stats = harvest(benign_sample, args.workers, "sah")

    if args.corpus_dir:
        os.makedirs(args.corpus_dir, exist_ok=True)
        for name, pages in (("judol", judol_pages), ("benign", benign_pages)):
            with open(os.path.join(args.corpus_dir, f"{name}.jsonl"), "w") as fh:
                for p in pages:
                    fh.write(json.dumps(p, ensure_ascii=False) + "\n")

    df_bad = doc_frequency(judol_pages)
    df_good = doc_frequency(benign_pages)
    rows = rank_terms(df_bad, len(judol_pages), df_good, len(benign_pages))

    with open(args.report, "w", encoding="utf-8") as fh:
        w = fh.write
        w("# Kalibrasi kata dari isi halaman\n\n")
        w(f"Dibuat: {datetime.now(timezone.utc).isoformat()}\n\n")
        w(f"- Halaman judol ASLI: **{len(judol_pages)}** dari {len(judol_sample)} domain dicoba\n")
        w(f"  - disaring sebagai halaman blokir ISP: {judol_stats['blokir']:,}\n")
        w(f"  - disaring sebagai halaman parkir: {judol_stats['parkir']:,}\n")
        w(f"  - mati / tidak merespons: {judol_stats['gagal']:,}\n")
        w(f"- Halaman Indonesia sah: **{len(benign_pages)}** dari {len(benign_sample)} dicoba\n")
        w(f"  - disaring blokir/parkir: {benign_stats['blokir'] + benign_stats['parkir']:,}\n\n")
        w("`df judol` = berapa halaman judol memuat kata itu. `df sah` = idem di korpus\n")
        w("pembanding. Lift = rasio pangsanya. Kata dengan df sah tinggi adalah kata\n")
        w("Indonesia biasa dan TIDAK boleh dipakai sebagai penanda.\n\n")
        w("| kata | df judol | % judol | df sah | % sah | lift |\n")
        w("|---|---:|---:|---:|---:|---:|\n")
        for t, cb, cg, sb, sg, lift in rows:
            w(f"| {t} | {cb} | {sb:.1%} | {cg} | {sg:.1%} | {lift:,.0f}× |\n")

    print(f"\nLaporan: {args.report}", file=sys.stderr)


if __name__ == "__main__":
    main()

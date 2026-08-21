# Laporan kalibrasi blocklist

Dibuat: 2026-08-12T03:22:15.405561+00:00

Sumber: [Lyra — ITSEC Research](https://github.com/ITSEC-Research/Lyra), acuan domain sah: Tranco top 1M.

## Bloom filter

- Kategori: suspicious, malicious, gambling
  - suspicious: 333,300
  - malicious: 2,120,336
  - gambling: 1,828,090
- Domain unik setelah gabung: 4,108,088
- Disaring dari malicious/suspicious (top 50,000 Tranco): gambling −334, malicious −1,005, suspicious −1,453
- Domain populer yang tetap masuk (dari gambling, disengaja): 194 — 1win.com, 1xbet.com, 1xbet.kz, 66lottery.vip, 789bingo.com, 888casino.com, adjarabet.am, adjarabet.com
- Ukuran aset: 9.4 MB (m=78,752,528 bit, k=13)
- Target false positive: 0.0100%

## TLD paling disalahgunakan

Lift = pangsa di daftar jahat ÷ pangsa di daftar situs populer. Lift tinggi berarti TLD itu memang sarang, bukan sekadar populer.

| TLD | jahat | populer | lift |
|---|---:|---:|---:|
| .tk | 11,640 | 31 | 89× |
| .gdn | 3,529 | 9 | 86× |
| .stream | 40,918 | 120 | 82× |
| .beer | 15,848 | 61 | 62× |
| .review | 3,319 | 15 | 50× |
| .digital | 64,635 | 421 | 37× |
| .boats | 4,853 | 35 | 33× |
| .loan | 1,847 | 13 | 32× |
| .motorcycles | 2,847 | 23 | 29× |
| .irish | 976 | 9 | 24× |
| .gq | 904 | 9 | 22× |
| .autos | 8,087 | 92 | 21× |
| .click | 109,006 | 1,267 | 21× |
| .homes | 9,159 | 113 | 20× |
| .sbs | 50,200 | 662 | 18× |
| .lol | 57,568 | 829 | 17× |
| .christmas | 866 | 12 | 16× |
| .cf | 1,194 | 17 | 16× |
| .forum | 6,049 | 91 | 16× |
| .beauty | 5,355 | 82 | 16× |
| .rest | 9,570 | 157 | 15× |
| .pics | 11,658 | 202 | 14× |
| .yoga | 685 | 11 | 14× |
| .college | 838 | 14 | 14× |
| .cyou | 24,257 | 445 | 13× |
| .makeup | 2,542 | 47 | 13× |
| .download | 2,823 | 53 | 13× |
| .skin | 4,928 | 94 | 13× |
| .bid | 4,927 | 97 | 12× |
| .hair | 3,155 | 63 | 12× |
| .quest | 5,634 | 117 | 12× |
| .icu | 30,757 | 654 | 11× |
| .poker | 558 | 11 | 11× |
| .yachts | 2,116 | 46 | 11× |
| .garden | 1,569 | 35 | 11× |
| .buzz | 33,044 | 798 | 10× |
| .ga | 1,192 | 28 | 10× |
| .help | 6,622 | 166 | 10× |
| .today | 12,889 | 326 | 10× |
| .vu | 1,198 | 30 | 9× |

### Usulan CHEAP_TLDS

```kotlin
        "tk", "gdn", "stream", "beer", "review", "digital", "boats", "loan",
        "motorcycles", "irish", "gq", "autos", "click", "homes", "sbs", "lol",
        "christmas", "cf", "forum", "beauty", "rest", "pics", "yoga", "college",
        "cyou", "makeup", "download", "skin", "bid", "hair", "quest", "icu",
        "poker", "yachts", "garden", "buzz", "ga", "help", "today", "vu",
        "store", "art", "site", "xyz", "lat", "ml", "rent", "bond"
```

## Kata penanda judi (kontras vs kategori lain + situs populer)

| kata | di judi | di kategori lain | di populer | lift |
|---|---:|---:|---:|---:|
| kudetabet | 1,400 | 0 | 3 | 483× |
| rtp | 23,040 | 121 | 81 | 177× |
| dku | 980 | 1 | 6 | 157× |
| dslot | 1,173 | 12 | 3 | 145× |
| dvip | 949 | 5 | 6 | 119× |
| kaisar | 1,281 | 6 | 10 | 105× |
| madridbet | 1,834 | 14 | 13 | 99× |
| mabar | 888 | 2 | 9 | 93× |
| alternatif | 1,164 | 7 | 10 | 92× |
| gacor | 9,029 | 91 | 68 | 86× |
| pola | 937 | 6 | 10 | 76× |
| asik | 985 | 13 | 8 | 74× |
| joycasino | 1,467 | 34 | 6 | 72× |
| yuk | 806 | 11 | 7 | 70× |
| dwin | 1,070 | 10 | 12 | 67× |
| catcasino | 1,682 | 61 | 1 | 62× |
| keren | 992 | 4 | 15 | 61× |
| jago | 988 | 12 | 12 | 59× |
| pragmatic | 969 | 16 | 10 | 58× |
| daftar | 1,763 | 15 | 25 | 58× |
| mpo | 5,095 | 52 | 69 | 57× |
| rupiah | 1,006 | 6 | 16 | 56× |
| terbaik | 922 | 5 | 15 | 55× |
| cuan | 4,121 | 61 | 52 | 54× |
| pasti | 1,059 | 8 | 17 | 53× |
| menang | 1,463 | 17 | 21 | 53× |
| amp | 5,009 | 99 | 62 | 49× |
| situs | 1,646 | 23 | 25 | 48× |
| sukses | 884 | 4 | 18 | 46× |
| oke | 2,000 | 26 | 34 | 45× |
| jojobet | 3,980 | 104 | 45 | 45× |
| gcr | 1,074 | 40 | 7 | 45× |
| juragan | 880 | 19 | 12 | 44× |
| slot | 23,769 | 555 | 308 | 44× |
| angkasa | 847 | 20 | 11 | 44× |
| mantap | 1,885 | 18 | 37 | 43× |
| bos | 2,750 | 53 | 44 | 42× |
| gbo | 946 | 4 | 22 | 41× |
| jitu | 1,517 | 21 | 30 | 40× |
| asli | 2,185 | 20 | 48 | 40× |
| klik | 1,150 | 16 | 23 | 39× |
| panen | 1,528 | 27 | 28 | 39× |
| sakti | 1,013 | 6 | 24 | 39× |
| sultan | 1,380 | 23 | 28 | 37× |
| jos | 1,139 | 26 | 21 | 36× |
| pokerdom | 1,129 | 35 | 17 | 36× |
| koin | 826 | 9 | 20 | 36× |
| kbet | 1,159 | 68 | 5 | 34× |
| agen | 1,933 | 52 | 36 | 34× |
| hoki | 6,362 | 200 | 109 | 33× |
| bola | 2,006 | 33 | 49 | 33× |
| bandar | 892 | 21 | 20 | 31× |
| jaya | 2,048 | 29 | 55 | 31× |
| maxwin | 3,360 | 116 | 63 | 30× |
| macau | 817 | 25 | 17 | 30× |
| idn | 1,095 | 36 | 22 | 30× |
| raja | 2,871 | 100 | 57 | 29× |
| aman | 871 | 11 | 26 | 29× |
| poker | 1,696 | 60 | 34 | 29× |
| vvip | 1,638 | 97 | 16 | 29× |

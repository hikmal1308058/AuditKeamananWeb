# AuditKeamananWeb

Implementasi algoritma `AuditKeamananWeb(daftar_target)` dalam Python (hanya pustaka standar, Python 3.9+).
Mengaudit lalu menghasilkan `laporan_audit`: daftar objek hasil, masing-masing berisi temuan, skor 0-100,
dan grade A-D. Bisa dipakai lewat baris perintah (CLI), sebagai pustaka Python, atau lewat **aplikasi
desktop (GUI)** — lihat [`gui_desktop.py`](#aplikasi-desktop-gui).

> **Gunakan hanya pada sistem milik sendiri atau yang Anda punya izin tertulis untuk menguji.**
> Pemindaian tanpa izin dapat melanggar hukum (di Indonesia, mis. UU ITE). Karena itu tool ini
> menolak target yang tidak ada di daftar izin (langkah 2b), dan modul yang lebih aktif (lihat
> di bawah) mewajibkan penegasan izin terpisah.

## Modul yang tersedia

| # | Modul | Sifat | Nyala bawaan? |
|---|---|---|---|
| 1 | TLS & sertifikat | Pasif (1 handshake TLS) | Ya |
| 2 | HTTP headers & cookie | Pasif (1 permintaan GET) | Ya |
| 3 | Integritas konten (hash SHA-256 vs baseline) | Pasif, opsional | Tidak (butuh `--baseline`) |
| 4 | Penilaian risiko & skor | — (selalu menghitung skor dari temuan modul lain) | Ya |
| 5 | Eksposur path/file sensitif (`.env`, `.git`, backup, dll.) | Mengirim ±18 GET tambahan | **Tidak** — opt-in |
| 6 | Pindai port umum (FTP, SMB, database, RDP, dll.) | TCP connect scan, tanpa payload | **Tidak** — opt-in |
| 7 | Cocokkan versi (dari header yang sudah terbaca) vs CVE publik | Pasif murni, tanpa request tambahan | Ya |

**Modul 5 dan 6 TIDAK melakukan eksploitasi.** Modul 5 hanya mengetikkan path yang sama seperti yang bisa
diakses siapa pun lewat browser (GET biasa) dan melihat apakah isinya terkirim. Modul 6 hanya mencoba
`connect()` ke sebuah port (seperti mengetuk pintu untuk tahu terkunci atau tidak), tanpa mengirim data
setelahnya. Keduanya **tidak** mengirim payload SQL injection/XSS, tidak mencoba login/brute-force, dan
tidak mengeksploitasi kerentanan apa pun — itu di luar cakupan alat ini (lihat juga "Yang sengaja TIDAK
dibuat" di bawah). Karena keduanya tetap lebih "aktif" daripada sekadar membaca header, keduanya **mati
secara bawaan** dan mewajibkan flag `--saya-punya-izin` (CLI) atau mencentang kotak penegasan izin (GUI)
sebelum berjalan — terpisah dari daftar izin domain di langkah 2b.

## Cara pakai (CLI)

```bash
# 1. Daftarkan domain yang boleh diaudit di izin.txt (domain uji bawaan sudah diizinkan)
# 2. Jalankan
python -m auditkeamananweb -f targets.txt --izin izin.txt --json laporan.json

# Target langsung dari argumen
python -m auditkeamananweb https://situs-saya.ac.id --izin izin.txt

# Dengan Modul 3 (integritas konten): rekam baseline, lalu bandingkan di jalankan berikutnya
python -m auditkeamananweb situs-saya.ac.id --izin izin.txt --baseline baseline.json --simpan-baseline
python -m auditkeamananweb situs-saya.ac.id --izin izin.txt --baseline baseline.json

# Dengan Modul 5 & 6 (wajib tegaskan izin terlebih dahulu)
python -m auditkeamananweb situs-saya.ac.id --izin izin.txt \
    --cek-eksposur --pindai-port --saya-punya-izin
```

| Opsi | Fungsi |
|---|---|
| `target ...` / `-f BERKAS` | URL atau domain/subdomain (argumen dan/atau berkas, satu per baris) |
| `--izin BERKAS` | Daftar domain yang diizinkan (`host` atau `*.domain`) |
| `--tanpa-domain-uji` | Matikan domain uji bawaan |
| `--timeout T` | Timeout koneksi, default 8 detik |
| `--redirect R` | Maksimum redirect diikuti, default 5 |
| `--baseline BERKAS` | Aktifkan Modul 3 dengan berkas hash baseline |
| `--simpan-baseline` | Rekam hash untuk target yang belum punya baseline |
| `--perbarui-baseline` | Timpa baseline bila konten berubah (setelah ditinjau) |
| `--cek-eksposur` | Modul 5: cek path/file sensitif (butuh `--saya-punya-izin`) |
| `--pindai-port` | Modul 6: pindai port umum (butuh `--saya-punya-izin`) |
| `--timeout-port T` | Timeout per percobaan koneksi port, default 1.5 detik |
| `--tanpa-cek-cve` | Matikan Modul 7 (aktif bawaan karena pasif) |
| `--saya-punya-izin` | **Wajib** bersama `--cek-eksposur`/`--pindai-port`: menegaskan Anda punya izin tertulis |
| `--json BERKAS` | Simpan laporan lengkap sebagai JSON |

Sebagai pustaka:

```python
from auditkeamananweb import audit_keamanan_web, KonfigAudit, Otorisasi

laporan_audit = audit_keamanan_web(
    ["situs-saya.ac.id", "https://api.situs-saya.ac.id:8443/"],
    otorisasi=Otorisasi(["situs-saya.ac.id", "*.situs-saya.ac.id"]),
    konfig=KonfigAudit(
        timeout=5, maks_redirect=3,
        cek_eksposur=True, pindai_port=True,  # hanya setelah Anda memastikan izinnya
    ),
)
for h in laporan_audit:
    print(h.target, h.status, h.skor, h.grade)
```

## Aplikasi desktop (GUI)

`gui_desktop.py` adalah antarmuka jendela untuk alat yang sama, dibangun dengan **tkinter** (bawaan
Python — tidak ada dependensi tambahan untuk MENJALANKANNYA dari source):

```bash
python gui_desktop.py
```

Tampilannya: kotak daftar target & daftar izin di kiri, kotak centang untuk tiap modul (termasuk
penegasan izin untuk Modul 5/6), tombol **Jalankan Audit**, lalu hasil per target muncul di panel
kanan secara bertahap (audit berjalan di thread latar sehingga jendela tidak macet), dengan tombol
untuk menyimpan hasil sebagai `.txt` atau `.json`.

### Membangun jadi satu berkas `.exe` (Windows)

1. Salin seluruh folder project ini ke komputer Windows (butuh Python 3.9+ dari python.org terpasang).
2. Jalankan `build_exe.bat` dengan dobel klik, atau lewat Command Prompt di folder project:
   ```bat
   build_exe.bat
   ```
3. Hasilnya ada di `dist\AuditKeamananWeb.exe` — berkas ini bisa disalin ke komputer Windows lain
   tanpa Python terpasang.

Build **harus** dilakukan di Windows (PyInstaller membuat `.exe` untuk sistem operasi tempat ia
dijalankan; tidak bisa dibangun dari Linux/Mac lalu dipakai di Windows). Di Linux/Mac, jalankan
perintah yang sama tanpa `.bat` (`pip install -r requirements-dev.txt && pyinstaller --onefile
--windowed --name AuditKeamananWeb gui_desktop.py`) untuk mendapatkan aplikasi mandiri di OS itu.

Setelah `AuditKeamananWeb.exe` jadi (di komputer mana pun ia dibangun), **salin berkas `.exe` itu
sendiri** ke laptop lain lewat flashdisk/WhatsApp/Google Drive — laptop tujuan tidak perlu Python
maupun folder project ini sama sekali, cukup satu berkas itu.

### Tidak punya komputer Windows sama sekali? Pakai GitHub Actions (gratis, otomatis)

Project ini sudah menyertakan `.github/workflows/build-windows-exe.yml` yang membangun `.exe` di
komputer Windows milik GitHub (gratis untuk repo publik), tanpa Anda perlu komputer Windows:

1. Buat akun GitHub (gratis) di [github.com](https://github.com) bila belum punya.
2. Buat repository baru (New repository), lalu unggah **seluruh isi folder project ini** ke
   repository tersebut (lewat tombol "uploading an existing file" di halaman repo kosong — bisa
   drag-and-drop semua berkas lewat browser, tidak perlu paham `git`).
3. Buka tab **Actions** di repo tersebut. Workflow "Build Windows .exe" akan otomatis berjalan
   (±2-3 menit). Kalau tidak otomatis jalan, klik workflow itu lalu tombol **Run workflow**.
4. Setelah selesai (tanda centang hijau), klik run tersebut, lalu unduh **Artifacts** bernama
   `AuditKeamananWeb-exe` di bagian bawah halaman. Itu berisi `AuditKeamananWeb.exe` yang siap
   dibagikan ke laptop Windows mana pun.

> Catatan: di beberapa distro Linux, tkinter perlu dipasang terpisah dari Python
> (mis. `sudo apt install python3-tk`); di installer resmi Windows/Mac dari python.org,
> tkinter sudah ikut terpasang.

## Pemetaan algoritma ke kode

| Langkah algoritma | Berkas |
|---|---|
| 1, 2, 3 (alur utama, penyimpanan hasil) | `auditkeamananweb/auditor.py` |
| 2a Normalisasi & validasi (hostname, port, path) | `target.py` |
| 2b Cek otorisasi, `SKIPPED (Unauthorized)` | `otorisasi.py` |
| 2c Modul 1: TLS & sertifikat | `modul_tls.py` |
| 2d Modul 2: HTTP headers & cookie | `modul_http.py` |
| 2e Modul 3: integritas konten (SHA-256 vs baseline) | `modul_integritas.py` |
| 2f Modul 4: skor & grade | `skor.py` |
| Modul 5: eksposur path/file sensitif (opt-in) | `modul_eksposur.py` |
| Modul 6: pindai port umum (opt-in) | `modul_port.py` |
| Modul 7: cocokkan versi vs CVE publik | `modul_cve.py` |
| Struktur data hasil | `models.py` |
| Format keluaran teks/JSON, CLI | `laporan.py`, `cli.py` |
| Aplikasi desktop (GUI) | `gui_desktop.py` |

## Status per target

`DIPERIKSA`, `SKIPPED (Unauthorized)`, `ERROR (Network)` (koneksi TCP gagal; lanjut ke target berikutnya),
`INVALID` (target tidak bisa dinormalisasi), `ERROR (Internal)`. Skor dan grade hanya ada pada `DIPERIKSA`.

## Aturan penilaian

Skor awal 100, minimum 0. Pengurangan: CRITICAL -25, HIGH -15, MEDIUM -8, LOW -3, INFO 0.
Grade: **A** >= 85, **B** >= 70, **C** >= 50, **D** < 50.

| Temuan | Level |
|---|---|
| SSLv2/SSLv3 atau cipher NULL/anonim (ADH/AECDH) | CRITICAL |
| Sertifikat kedaluwarsa | CRITICAL |
| TLS 1.0/1.1, cipher RC4/3DES/MD5 | HIGH |
| Self-signed/tidak tepercaya, hostname tidak cocok, belum berlaku | HIGH |
| Target hanya HTTP tanpa TLS, redirect HTTPS -> HTTP, handshake TLS gagal | HIGH |
| Sertifikat sisa <= 14 hari | MEDIUM (<= 30 hari: LOW) |
| HSTS/CSP/anti-clickjacking hilang, HSTS tidak valid | MEDIUM |
| Cookie tanpa Secure atau HttpOnly, `SameSite=None` tanpa Secure | MEDIUM |
| Konten berbeda dari baseline | MEDIUM (perlu ditinjau manual) |
| HSTS max-age < 180 hari, CSP `unsafe-inline/eval`, nosniff / Referrer-Policy / Permissions-Policy hilang, cookie tanpa SameSite, banner server membuka versi | LOW |
| Path sensitif terekspos (`.env`, `.git`, dump database, kunci SSH, dll.) | CRITICAL/HIGH (lihat `modul_eksposur.py`) |
| Panel admin/phpMyAdmin pada path umum dapat diakses | LOW/MEDIUM |
| Port database/FTP/Telnet/SMB terbuka ke publik | HIGH |
| Port RDP/VNC/RPC/NetBIOS terbuka ke publik | MEDIUM |
| Versi software yang terbaca dari header cocok dengan CVE/EOL publik | MEDIUM-CRITICAL (indikasi awal, **wajib diverifikasi manual**) |

Temuan cookie **digabung per jenis masalah** (satu temuan memuat semua nama cookie terkait), sehingga
situs dengan 20 cookie tidak otomatis mendapat skor 0. Nilai cookie tidak pernah dicatat ke laporan.

## Keputusan desain dan batasan

- **Redirect hanya diikuti ke host yang juga diotorisasi.** Redirect ke host lain dicatat dan dihentikan,
  agar audit tidak "menyeberang" ke sistem yang tidak berizin.
- **Header HSTS tidak dituntut pada URL `http://`** (HSTS memang diabaikan browser lewat HTTP); sebagai gantinya muncul temuan `TLS_TANPA_ENKRIPSI`.
- **Validitas sertifikat hanya dinilai di Modul 1.** Modul 2 membaca header tanpa verifikasi sertifikat supaya situs
  dengan sertifikat bermasalah tetap bisa diperiksa header-nya.
- **Deteksi protokol lemah** memakai versi yang dinegosiasikan. Bila klien modern gagal handshake, tool mencoba
  sekali lagi dengan konfigurasi longgar untuk mendeteksi server legasi. Ini bukan pemindai lengkap seluruh
  protokol/cipher yang didukung server (untuk itu pakai `testssl.sh` atau `sslyze`).
- **Sisa hari sertifikat** pada sertifikat yang gagal verifikasi hanya terbaca jika paket opsional
  `cryptography` terpasang (`pip install -r requirements-opsional.txt`); selain itu bernilai `None`.
- **Modul 3 memakai maksimum 2 MiB pertama** dari body. Halaman dinamis (iklan, token CSRF, waktu) bisa memberi
  hash berbeda tanpa defacement, karena itu hasilnya hanya "perlu ditinjau".
- Wildcard izin pada sufiks publik umum (`*.com`, `*.ac.id`, `*.co.id`, ...) ditolak sebagai pengaman salah ketik.
- **Modul 5 & 6 mati secara bawaan** dan butuh `--saya-punya-izin`/kotak centang terpisah di GUI, di
  luar daftar izin domain, karena keduanya mengirim lebih banyak permintaan daripada sekadar membaca
  header (Modul 5: ±18 GET tambahan; Modul 6: beberapa percobaan koneksi TCP ke port lain).
- **Modul 5 punya pengaman anti-false-positive bawaan.** Sebelum menilai path mana pun, modul mengirim
  satu permintaan "kontrol" ke path acak yang pasti tidak ada. Bila sebuah path sensitif memberi status
  dan isi yang IDENTIK dengan path kontrol itu, temuan itu DISARING (bukan dilaporkan sebagai eksposur),
  karena itu tandanya server punya halaman generik untuk "tidak ditemukan" -- baik lewat 403 blanket
  (mis. aturan WAF pada banyak situs instansi) maupun 200 catch-all (mis. SPA yang selalu membalas
  `index.html`) -- bukan bukti berkas itu betulan ada. Saat ini terjadi, muncul satu temuan INFO
  `EKSPOSUR_POLA_GENERIK_TERDETEKSI` yang menyebut berapa banyak path tersaring.
- **Modul 7 hanya heuristik berbasis nomor versi dari banner yang sudah terbaca** (bukan pemindaian CVE
  aktif/online). Banner bisa disamarkan admin, dan patch keamanan kadang di-backport tanpa mengubah
  nomor versi -- hasil "berpotensi rentan" WAJIB diverifikasi manual, bukan vonis pasti.

### Yang sengaja TIDAK dibuat (dan alasannya)

Alat ini dibuat untuk audit yang aman dijalankan rutin tanpa risiko merusak atau membebani sistem
target. Karena itu, hal-hal berikut **tidak** dan tidak akan ditambahkan ke tool ini:

- Payload SQL injection, XSS, command injection, atau eksploitasi kerentanan lain yang sudah terdeteksi.
- Brute-force/credential stuffing login, atau percobaan menebak kredensial dengan cara apa pun.
- Serangan denial-of-service (flood, stress test) atau pengujian beban.
- Pemindaian CVE lewat basis data online pihak ketiga (basis data Modul 7 sengaja kecil & lokal).

Untuk pengujian penetrasi aktif yang sah (butuh izin tertulis yang jelas, biasanya dalam bentuk kontrak
*rules of engagement*), gunakan alat khusus seperti OWASP ZAP, Burp Suite, Nikto, atau nmap dengan
skrip NSE -- dan idealnya dilakukan oleh/berkonsultasi dengan pihak yang berkompeten di bidang
keamanan ofensif.

## Pengujian

```bash
python -m unittest discover -s tests -t . -v
```

55 tes mencakup normalisasi, otorisasi, aturan TLS/header/cookie/eksposur/port/CVE (termasuk penyaringan
pola generik 403-blanket dan 200-catch-all di Modul 5), skor, baseline, pengujian konsensus CLI
(`--saya-punya-izin`), serta uji integrasi ke server HTTP dan HTTPS (sertifikat self-signed lokal) di
`127.0.0.1`, sehingga tidak butuh internet. Tes TLS dilewati otomatis bila `openssl` tidak tersedia.

`gui_desktop.py` tidak otomatis diuji di sini (butuh tampilan/display, dan lingkungan pembuatan project
ini tidak punya satu), tapi sudah dicek dengan `pyright` (type checker statis) tanpa galat, dan seluruh
fungsi inti yang dipakainya (`audit_keamanan_web`, `format_teks`, `ke_json`, `Baseline`, `Otorisasi`)
sudah teruji lewat 53 tes di atas. Uji dulu `python gui_desktop.py` di komputer Anda sebelum memakainya
untuk audit yang sesungguhnya.

## Ide pengembangan

Laporan HTML/Markdown, audit paralel (`ThreadPoolExecutor`), pengecekan cookie berprefiks `__Host-`,
daftar path/port yang bisa dikonfigurasi dari GUI (saat ini hanya lewat parameter pustaka), serta
penjadwalan audit rutin dengan pembandingan skor antar waktu.

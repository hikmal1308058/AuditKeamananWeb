"""MODUL 5: EKSPOSUR PATH/FILE SENSITIF (opt-in, non-destruktif).

Hanya mengirim permintaan GET biasa ke path yang sama seperti yang bisa diketikkan
siapa pun di browser (bukan payload serangan). Tujuannya mendeteksi file konfigurasi,
backup, atau panel admin yang tidak sengaja terekspos publik.

ANTI-FALSE-POSITIVE: sebelum menilai path mana pun, modul ini dulu mengirim satu
permintaan "kontrol" ke path acak yang (hampir pasti) tidak pernah ada di server
mana pun. Jika sebuah path sensitif memberi status DAN isi yang SAMA PERSIS dengan
path acak itu, itu tandanya server punya halaman generik untuk "path tidak ditemukan"
(baik lewat 403 blanket/WAF, maupun lewat 200 catch-all seperti SPA yang selalu
mengembalikan index.html) -- bukan bukti bahwa file itu benar-benar ada. Temuan
seperti itu DISARING, bukan dilaporkan sebagai eksposur.
"""
from __future__ import annotations

import hashlib
import http.client
import secrets
import ssl
from dataclasses import dataclass

from .models import Finding, Level
from .target import TargetTerurai

MODUL = "EKSPOSUR"

# (path, level jika TERBUKA, keterangan). Daftar kecil & umum secara sengaja —
# ini bukan pemindai kerentanan lengkap (lihat README untuk alat yang lebih menyeluruh).
DAFTAR_PATH_BAWAAN: tuple[tuple[str, Level, str], ...] = (
    ("/.env", Level.CRITICAL, "Berkas konfigurasi lingkungan (kredensial, API key)"),
    ("/.git/config", Level.CRITICAL, "Metadata repositori Git (bisa membocorkan seluruh source code)"),
    ("/.git/HEAD", Level.CRITICAL, "Metadata repositori Git"),
    ("/wp-config.php.bak", Level.CRITICAL, "Backup konfigurasi WordPress (kredensial database)"),
    ("/config.php.bak", Level.HIGH, "Backup berkas konfigurasi"),
    ("/.svn/entries", Level.HIGH, "Metadata repositori Subversion"),
    ("/database.sql", Level.CRITICAL, "Dump database mentah"),
    ("/backup.zip", Level.HIGH, "Arsip backup"),
    ("/backup.sql", Level.HIGH, "Dump database"),
    ("/phpinfo.php", Level.MEDIUM, "Info konfigurasi PHP & server (reconnaissance)"),
    ("/.htpasswd", Level.HIGH, "Berkas kredensial Basic Auth"),
    ("/.aws/credentials", Level.CRITICAL, "Kredensial AWS"),
    ("/id_rsa", Level.CRITICAL, "Kunci privat SSH"),
    ("/server-status", Level.MEDIUM, "Status internal Apache (mod_status) dapat membocorkan request pengguna lain"),
    ("/admin/", Level.LOW, "Panel admin dapat diakses pada path umum"),
    ("/phpmyadmin/", Level.MEDIUM, "Panel phpMyAdmin dapat diakses pada path umum"),
    ("/.DS_Store", Level.LOW, "Metadata macOS dapat membocorkan struktur folder"),
)

_UKURAN_CUPLIKAN = 4096  # cukup untuk membandingkan isi tanpa mengunduh seluruh berkas besar


@dataclass
class HasilPath:
    path: str
    status: int | None
    keterangan: str


def _ambil_ringkasan(t: TargetTerurai, path: str, timeout: float) -> tuple[int | None, str | None]:
    """Kembalikan (status, sha256 dari ~4 KiB pertama isi). (None, None) bila gagal konek."""
    if t.skema == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            t.hostname, t.port, timeout=timeout, context=ctx
        )
    else:
        conn = http.client.HTTPConnection(t.hostname, t.port, timeout=timeout)
    try:
        conn.request("GET", path, headers={
            "User-Agent": "AuditKeamananWeb/1.0 (audit terotorisasi)",
            "Connection": "close",
        })
        resp = conn.getresponse()
        cuplikan = resp.read(_UKURAN_CUPLIKAN)
        return resp.status, hashlib.sha256(cuplikan).hexdigest()
    except (OSError, http.client.HTTPException):
        return None, None
    finally:
        conn.close()


def _path_kontrol() -> str:
    return f"/_auditkeamananweb_cek_{secrets.token_hex(10)}_tidak_pernah_ada"


def periksa_eksposur(
    t: TargetTerurai,
    timeout: float = 5.0,
    daftar_path: tuple[tuple[str, Level, str], ...] = DAFTAR_PATH_BAWAAN,
) -> tuple[list[Finding], dict]:
    """Jalankan Modul 5. Satu permintaan GET per path (plus satu permintaan kontrol),
    dijalankan berurutan (bukan paralel) agar tidak membebani server target."""
    status_kontrol, hash_kontrol = _ambil_ringkasan(t, _path_kontrol(), timeout)
    pola_generik_terdeteksi = status_kontrol in (200, 206, 403)

    ditemukan: list[HasilPath] = []
    disaring: list[str] = []
    for path, level, keterangan in daftar_path:
        status, h = _ambil_ringkasan(t, path, timeout)
        # 200/206 = isi terkirim; 403 masih bisa menandakan berkas ADA (ditolak Apache/Nginx) --
        # KECUALI responsnya identik (status & isi) dengan path kontrol yang tidak pernah ada,
        # yang berarti itu cuma halaman generik server, bukan bukti berkas itu ada.
        if status not in (200, 206, 403):
            continue
        identik_dengan_kontrol = status == status_kontrol and h == hash_kontrol and h is not None
        if identik_dengan_kontrol:
            disaring.append(path)
            continue
        ditemukan.append(HasilPath(path, status, keterangan))

    findings = [
        Finding(
            MODUL, "EKSPOSUR_PATH_TERBUKA",
            next(lv for p, lv, _ in daftar_path if p == h.path),
            f"Path berpotensi terekspos: {h.path} (HTTP {h.status})",
            h.keterangan,
            "Blokir akses publik ke path ini lewat konfigurasi server/.htaccess, atau hapus bila tidak perlu.",
        )
        for h in ditemukan
    ]
    if pola_generik_terdeteksi:
        findings.append(Finding(
            MODUL, "EKSPOSUR_POLA_GENERIK_TERDETEKSI", Level.INFO,
            "Server memberi respons yang sama untuk path yang jelas tidak ada",
            f"Path kontrol acak mendapat HTTP {status_kontrol}. Temuan yang identik dengan pola ini "
            f"sudah otomatis disaring ({len(disaring)} dari {len(daftar_path)} path): "
            + (", ".join(disaring) if disaring else "tidak ada"),
            "Informasi saja -- bukan kerentanan. Menandakan WAF/aturan generik atau halaman "
            "fallback, bukan bukti berkas-berkas yang disaring benar-benar ada.",
        ))

    info = {
        "path_diperiksa": len(daftar_path),
        "path_terekspos": [{"path": h.path, "status": h.status} for h in ditemukan],
        "status_kontrol": status_kontrol,
        "path_disaring_pola_generik": disaring,
    }
    return findings, info

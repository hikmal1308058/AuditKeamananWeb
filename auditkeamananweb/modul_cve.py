"""MODUL 7: PENCOCOKAN VERSI vs KERENTANAN PUBLIK (opt-in, pasif).

PENTING: modul ini TIDAK mengeksploitasi apa pun. Ia hanya mencocokkan string versi
yang SUDAH terbaca dari header HTTP (mis. "Apache/2.4.49") dengan basis data kecil
kerentanan yang sudah diumumkan publik (CVE). Ini hanya indikasi awal berbasis nomor
versi — banyak vendor melakukan backport patch tanpa mengubah nomor versi, jadi hasil
"berpotensi rentan" WAJIB diverifikasi manual, bukan vonis pasti.

Basis data di bawah sengaja kecil & statis (bukan API online) supaya alat ini tetap
bisa dipakai tanpa koneksi ke basis data CVE pihak ketiga. Perbarui secara berkala
dari sumber resmi seperti https://nvd.nist.gov jika ingin cakupan lebih luas.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding, Level

MODUL = "CVE"

Versi = tuple[int, ...]


@dataclass(frozen=True)
class EntriCVE:
    produk: str  # dicari via regex "<produk>[/ ]<versi>" pada banner, case-insensitive
    versi_bawah: Versi  # inklusif; (0,) berarti tanpa batas bawah
    versi_atas: Versi  # EKSKLUSIF; versi >= ini dianggap aman dari entri ini
    cve: str
    level: Level
    ringkasan: str


# Daftar kecil & terkenal, disengaja: semuanya kerentanan/EOL versi lama yang sudah lama
# diumumkan publik dan sering dipakai sebagai contoh edukasi keamanan web.
BASIS_DATA_BAWAAN: tuple[EntriCVE, ...] = (
    EntriCVE("apache", (2, 4, 49), (2, 4, 51), "CVE-2021-41773 / CVE-2021-42013", Level.CRITICAL,
             "Path traversal & RCE pada Apache HTTP Server 2.4.49-2.4.50"),
    EntriCVE("nginx", (0,), (1, 17, 7), "CVE-2019-20372", Level.MEDIUM,
             "Request smuggling pada error_page di nginx versi lama"),
    EntriCVE("openssl", (1, 0, 1), (1, 0, 2), "CVE-2014-0160 (Heartbleed)", Level.CRITICAL,
             "Kebocoran memori server (Heartbleed) pada OpenSSL 1.0.1 hingga 1.0.1f"),
    EntriCVE("php", (0,), (5, 6, 40), "EOL", Level.HIGH, "PHP 5.x sudah End-of-Life"),
    EntriCVE("php", (7, 0, 0), (7, 2, 0), "EOL", Level.HIGH, "PHP 7.0/7.1 sudah End-of-Life"),
    EntriCVE("iis", (0,), (7, 0), "EOL", Level.HIGH, "IIS 6 ke bawah berjalan di Windows yang sudah End-of-Life"),
    EntriCVE("wordpress", (0,), (5, 0, 0), "banyak CVE lama", Level.HIGH,
             "WordPress 4.x ke bawah sudah lama tidak menerima tambalan keamanan rutin"),
)


def _ekstrak_versi(banner: str, produk: str) -> Versi | None:
    pola = re.compile(re.escape(produk) + r"[/\s]+v?(\d+(?:\.\d+){1,3})", re.I)
    m = pola.search(banner)
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def cocokkan_versi(banner: str, basis_data: tuple[EntriCVE, ...] = BASIS_DATA_BAWAAN) -> list[Finding]:
    """Cari produk dikenal di dalam satu string banner (mis. header Server)."""
    if not banner:
        return []
    hasil: list[Finding] = []
    sudah: set[str] = set()  # hindari dua entri produk sama melaporkan versi yang sama dua kali
    for entri in basis_data:
        versi = _ekstrak_versi(banner, entri.produk)
        if versi is None or not (versi >= entri.versi_bawah and versi < entri.versi_atas):
            continue
        teks_versi = ".".join(map(str, versi))
        kunci = f"{entri.produk}:{teks_versi}:{entri.cve}"
        if kunci in sudah:
            continue
        sudah.add(kunci)
        hasil.append(Finding(
            MODUL, "CVE_VERSI_BERPOTENSI_RENTAN", entri.level,
            f"Versi berpotensi rentan terdeteksi dari banner: {banner}",
            f"{entri.cve}: {entri.ringkasan}. Terdeteksi {entri.produk} versi {teks_versi}.",
            "VERIFIKASI MANUAL dulu (banner bisa salah/disamarkan, dan patch keamanan bisa "
            "di-backport tanpa mengubah nomor versi). Jika benar, segera perbarui ke versi terbaru.",
        ))
    return hasil


def cocokkan_banner_gabungan(banner_list: list[str]) -> tuple[list[Finding], dict]:
    """Jalankan Modul 7 atas beberapa sumber banner (Server, X-Powered-By, dll.)."""
    findings: list[Finding] = []
    for b in banner_list:
        findings += cocokkan_versi(b)
    info = {"banner_diperiksa": [b for b in banner_list if b]}
    return findings, info

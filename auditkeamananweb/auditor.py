"""Orkestrasi algoritma AuditKeamananWeb(daftar_target) -> laporan_audit."""
from __future__ import annotations

import http.client
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from . import modul_cve, modul_eksposur, modul_http, modul_port, modul_tls
from .modul_integritas import Baseline, periksa_integritas
from .models import (
    STATUS_INTERNAL, STATUS_INVALID, STATUS_NETWORK, STATUS_OK, STATUS_SKIPPED,
    Finding, HasilTarget, Level,
)
from .otorisasi import Otorisasi
from .skor import hitung_skor, tentukan_grade
from .target import TargetTidakValid, normalisasi_target


@dataclass
class KonfigAudit:
    timeout: float = 8.0  # T: timeout koneksi (detik)
    maks_redirect: int = 5  # R: maksimum redirect yang diikuti
    baseline: Baseline | None = None  # None -> Modul 3 dilewati
    simpan_baseline: bool = False  # rekam hash bila belum ada baseline
    perbarui_baseline: bool = False  # timpa baseline bila konten berubah
    sekarang: datetime | None = None  # untuk pengujian

    # --- Modul 5-7: non-destruktif, TAPI harus dinyalakan sendiri (default mati).
    # Mengaktifkannya berarti Anda menegaskan sudah punya izin untuk pengujian ini,
    # bukan hanya untuk audit header/TLS pasif.
    cek_eksposur: bool = False       # Modul 5: path/file sensitif
    pindai_port: bool = False        # Modul 6: TCP connect scan port umum
    cek_cve: bool = True             # Modul 7: cocokkan versi vs CVE publik (pasif, aman)
    timeout_port: float = 1.5        # timeout per percobaan koneksi port (detik)


def audit_keamanan_web(
    daftar_target: Iterable[str],
    otorisasi: Otorisasi | None = None,
    konfig: KonfigAudit | None = None,
) -> list[HasilTarget]:
    otorisasi = otorisasi or Otorisasi()
    konfig = konfig or KonfigAudit()

    laporan_audit: list[HasilTarget] = []  # 1. INISIALISASI
    for teks in daftar_target:  # 2. UNTUK SETIAP target
        try:
            hasil = _audit_satu(teks, otorisasi, konfig)
        except Exception as e:  # noqa: BLE001 - satu target rusak tidak boleh menghentikan audit
            hasil = HasilTarget(target=str(teks), status=STATUS_INTERNAL,
                                catatan=[f"{type(e).__name__}: {e}"])
        laporan_audit.append(hasil)  # 2g. simpan objek hasil

    if konfig.baseline is not None:
        konfig.baseline.simpan_jika_berubah()
    return laporan_audit  # 3. KEMBALIKAN laporan_audit


def _audit_satu(teks: str, otorisasi: Otorisasi, konfig: KonfigAudit) -> HasilTarget:
    hasil = HasilTarget(target=teks)

    # 2a. Normalisasi & validasi
    try:
        t = normalisasi_target(teks)
    except TargetTidakValid as e:
        hasil.status = STATUS_INVALID
        hasil.catatan.append(str(e))
        return hasil
    hasil.hostname, hasil.port, hasil.skema, hasil.path = t.hostname, t.port, t.skema, t.path

    # 2b. Cek otorisasi
    if not otorisasi.diizinkan(t.hostname):
        hasil.status = STATUS_SKIPPED
        hasil.catatan.append(
            f"Host '{t.hostname}' tidak ada di daftar izin; tidak ada permintaan yang dikirim."
        )
        return hasil

    # 2c. Modul 1: TLS & sertifikat
    try:
        if t.skema == "https":
            temuan_tls, info_tls = modul_tls.periksa_tls(
                t.hostname, t.port, konfig.timeout, konfig.sekarang
            )
            hasil.findings += temuan_tls
            hasil.info["tls"] = info_tls
        else:
            modul_tls.uji_koneksi_tcp(t.hostname, t.port, konfig.timeout).close()
            hasil.info["tls"] = {"catatan": "Skema HTTP: pemeriksaan TLS tidak berlaku."}
            hasil.findings.append(Finding(
                "TLS", "TLS_TANPA_ENKRIPSI", Level.HIGH, "Target dilayani lewat HTTP tanpa enkripsi",
                f"{t.url} tidak memakai TLS.",
                "Layani situs lewat HTTPS dan arahkan seluruh trafik HTTP ke HTTPS.",
            ))
    except modul_tls.GagalKoneksi as e:
        hasil.status = STATUS_NETWORK
        hasil.catatan.append(f"Koneksi TCP ke {t.hostname}:{t.port} gagal: {e}")
        return hasil

    # 2d. Modul 2: HTTP headers & cookie
    respons = None
    if any(f.kode == "TLS_HANDSHAKE_GAGAL" for f in hasil.findings):
        hasil.catatan.append("Handshake TLS gagal total; Modul 2 dan 3 dilewati.")
    else:
        try:
            respons = modul_http.ambil_respons(
                t, timeout=konfig.timeout, maks_redirect=konfig.maks_redirect,
                diizinkan=otorisasi.diizinkan,
            )
        except (OSError, http.client.HTTPException) as e:
            hasil.findings.append(Finding(
                "HTTP", "HTTP_GAGAL", Level.MEDIUM, "Permintaan HTTP gagal",
                f"{type(e).__name__}: {e}",
                "Pastikan layanan web merespons permintaan GET biasa.",
            ))
        else:
            hasil.findings += modul_http.evaluasi_respons(respons)
            hasil.catatan += respons.catatan
            hasil.info["http"] = {
                "status": respons.status,
                "url_akhir": respons.url_akhir,
                "rantai_redirect": respons.rantai_redirect,
                "jumlah_cookie": len(respons.cookies),
                "ukuran_body_byte": len(respons.body),
                "body_terpotong": respons.terpotong,
            }

    # 2d.2 Modul 7: cocokkan banner/versi (dari header yang SUDAH terbaca) vs CVE publik.
    # Pasif murni -- tidak ada permintaan jaringan tambahan -- karena itu aman dinyalakan bawaan.
    if konfig.cek_cve and respons is not None:
        banner_list = [respons.header.get(k, "") for k in
                       ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")]
        temuan_cve, info_cve = modul_cve.cocokkan_banner_gabungan(banner_list)
        hasil.findings += temuan_cve
        if info_cve["banner_diperiksa"]:
            hasil.info["cve"] = info_cve

    # 2d.3 Modul 5: eksposur path/file sensitif (opt-in -- kirim beberapa GET tambahan).
    if konfig.cek_eksposur:
        temuan_eks, info_eks = modul_eksposur.periksa_eksposur(t, konfig.timeout)
        hasil.findings += temuan_eks
        hasil.info["eksposur"] = info_eks

    # 2d.4 Modul 6: pindai port umum (opt-in -- TCP connect scan, tanpa payload).
    if konfig.pindai_port:
        temuan_port, info_port = modul_port.pindai_port(t.hostname, konfig.timeout_port)
        hasil.findings += temuan_port
        hasil.info["port"] = info_port

    # 2e. Modul 3: integritas konten (opsional)
    if konfig.baseline is not None and respons is not None:
        temuan_int, info_int = periksa_integritas(
            t.url, respons.body, konfig.baseline, respons.terpotong,
            konfig.simpan_baseline, konfig.perbarui_baseline,
        )
        hasil.findings += temuan_int
        hasil.info["integritas"] = info_int

    # 2f. Modul 4: skor & grade
    hasil.skor = hitung_skor(hasil.findings)
    hasil.grade = tentukan_grade(hasil.skor)
    hasil.status = STATUS_OK
    return hasil

"""Antarmuka baris perintah."""
from __future__ import annotations

import argparse
import sys

from .auditor import KonfigAudit, audit_keamanan_web
from .laporan import format_teks, ke_json
from .modul_integritas import Baseline
from .otorisasi import Otorisasi
from .target import baca_daftar


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="auditkeamananweb",
        description="Audit keamanan web pasif (TLS, header HTTP, cookie, integritas konten). "
        "Gunakan HANYA pada sistem yang Anda miliki atau yang Anda punya izin tertulis untuk diuji.",
    )
    p.add_argument("target", nargs="*", help="URL atau domain/subdomain")
    p.add_argument("-f", "--berkas", action="append", default=[], metavar="BERKAS",
                   help="berkas daftar target (satu per baris); boleh berulang")
    p.add_argument("--izin", action="append", default=[], metavar="BERKAS",
                   help="berkas daftar domain yang diizinkan; boleh berulang")
    p.add_argument("--tanpa-domain-uji", action="store_true",
                   help="matikan domain uji bawaan (localhost, example.*, badssl.com)")
    p.add_argument("--timeout", type=float, default=8.0, help="timeout koneksi (detik), default 8")
    p.add_argument("--redirect", type=int, default=5, help="maksimum redirect diikuti, default 5")
    p.add_argument("--baseline", metavar="BERKAS", help="berkas baseline hash (mengaktifkan Modul 3)")
    p.add_argument("--simpan-baseline", action="store_true",
                   help="rekam hash untuk target yang belum punya baseline")
    p.add_argument("--perbarui-baseline", action="store_true",
                   help="timpa baseline jika konten berubah")
    p.add_argument("--json", metavar="BERKAS", help="simpan laporan lengkap sebagai JSON")

    g = p.add_argument_group(
        "Modul opt-in (non-destruktif, tapi lebih \"aktif\" dari sekadar membaca header)",
    )
    g.add_argument("--cek-eksposur", action="store_true",
                   help="Modul 5: cek path/file sensitif terekspos (.env, .git, backup, dll.) "
                        "lewat GET biasa -- tidak mengeksploitasi apa pun")
    g.add_argument("--pindai-port", action="store_true",
                   help="Modul 6: TCP connect scan ke port umum (FTP, SMB, database, RDP, dll.) "
                        "-- hanya cek terbuka/tertutup, tanpa mengirim payload")
    g.add_argument("--timeout-port", type=float, default=1.5,
                   help="timeout per percobaan koneksi port (detik), default 1.5")
    g.add_argument("--tanpa-cek-cve", action="store_true",
                   help="matikan Modul 7 (cocokkan versi dari header vs basis data CVE publik); "
                        "modul ini aktif secara bawaan karena murni pasif")
    g.add_argument(
        "--saya-punya-izin", action="store_true",
        help="WAJIB disertakan bila memakai --cek-eksposur dan/atau --pindai-port: menegaskan "
             "Anda punya izin tertulis dari pemilik target untuk pengujian ini, bukan hanya "
             "untuk audit header/TLS pasif.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    p = _parser()
    a = p.parse_args(argv)

    try:
        daftar = list(a.target)
        for berkas in a.berkas:
            daftar += baca_daftar(berkas)
        otorisasi = Otorisasi.dari_berkas(a.izin, sertakan_bawaan=not a.tanpa_domain_uji)
        baseline = Baseline(a.baseline) if a.baseline else None
    except (OSError, ValueError) as e:
        print(f"Kesalahan: {e}", file=sys.stderr)
        return 2

    if not daftar:
        p.error("tidak ada target. Beri target sebagai argumen atau lewat -f BERKAS.")
    if (a.simpan_baseline or a.perbarui_baseline) and baseline is None:
        p.error("--simpan-baseline/--perbarui-baseline membutuhkan --baseline BERKAS.")
    if (a.cek_eksposur or a.pindai_port) and not a.saya_punya_izin:
        p.error(
            "--cek-eksposur dan --pindai-port membutuhkan --saya-punya-izin sebagai penegasan "
            "bahwa Anda punya izin tertulis dari pemilik target untuk pengujian ini."
        )

    konfig = KonfigAudit(
        timeout=a.timeout,
        maks_redirect=a.redirect,
        baseline=baseline,
        simpan_baseline=a.simpan_baseline,
        perbarui_baseline=a.perbarui_baseline,
        cek_eksposur=a.cek_eksposur,
        pindai_port=a.pindai_port,
        cek_cve=not a.tanpa_cek_cve,
        timeout_port=a.timeout_port,
    )
    laporan = audit_keamanan_web(daftar, otorisasi, konfig)
    print(format_teks(laporan))

    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            f.write(ke_json(laporan))
        print(f"\nLaporan JSON disimpan ke {a.json}")
    return 0

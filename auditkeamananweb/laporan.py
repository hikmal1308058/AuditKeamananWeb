"""Pemformatan laporan_audit: teks untuk terminal dan JSON."""
from __future__ import annotations

import json
from collections import Counter
from typing import Iterable

from .models import STATUS_OK, STATUS_SKIPPED, URUTAN_LEVEL, HasilTarget


def ke_json(laporan: Iterable[HasilTarget]) -> str:
    return json.dumps([h.to_dict() for h in laporan], indent=2, ensure_ascii=False)


def format_teks(laporan: list[HasilTarget]) -> str:
    baris: list[str] = []
    for h in laporan:
        baris.append("=" * 72)
        baris.append(f"Target : {h.target}")
        baris.append(f"Status : {h.status}")
        if h.skor is not None:
            baris.append(f"Skor   : {h.skor}/100  (Grade {h.grade})")
        tls = h.info.get("tls", {})
        if tls.get("protokol"):
            baris.append(f"TLS    : {tls['protokol']} / {tls.get('cipher_suite', '-')}")
        if tls.get("sisa_hari") is not None:
            baris.append(f"Sertifikat: sisa {tls['sisa_hari']} hari")
        for c in h.catatan:
            baris.append(f"Catatan: {c}")
        urut = sorted(h.findings, key=lambda f: URUTAN_LEVEL.index(f.level))
        for f in urut:
            baris.append(f"  [{f.level.value:<8}] {f.kode}: {f.judul}")
            if f.detail:
                baris.append(f"      {f.detail}")
            if f.rekomendasi:
                baris.append(f"      -> {f.rekomendasi}")
        if h.status == STATUS_OK and not h.findings:
            baris.append("  Tidak ada temuan.")

    baris.append("=" * 72)
    status = Counter(h.status for h in laporan)
    grade = Counter(h.grade for h in laporan if h.grade)
    baris.append("RINGKASAN")
    baris.append(f"  Total target       : {len(laporan)}")
    baris.append(f"  Diperiksa          : {status.get(STATUS_OK, 0)}")
    baris.append(f"  Dilewati (izin)    : {status.get(STATUS_SKIPPED, 0)}")
    lain = len(laporan) - status.get(STATUS_OK, 0) - status.get(STATUS_SKIPPED, 0)
    baris.append(f"  Gagal/tidak valid  : {lain}")
    if grade:
        baris.append("  Sebaran grade      : " + ", ".join(f"{g}={grade[g]}" for g in sorted(grade)))
    return "\n".join(baris)

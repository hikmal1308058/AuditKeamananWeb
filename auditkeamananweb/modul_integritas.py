"""MODUL 3: INTEGRITAS KONTEN (OPSIONAL).

current_hash = SHA256(konten_terbaca) dibandingkan dengan baseline_hash tersimpan.
Perbedaan hanya ditandai "perlu ditinjau": halaman dinamis bisa berubah secara sah.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any

from .models import Finding, Level

MODUL = "INTEGRITAS"


def hitung_hash(konten: bytes) -> str:
    return hashlib.sha256(konten).hexdigest()


class Baseline:
    """Penyimpan hash baseline (berkas JSON): {"versi": 1, "entri": {url: {sha256, waktu}}}."""

    def __init__(self, jalur: str) -> None:
        self.jalur = jalur
        self._entri: dict[str, dict[str, str]] = {}
        self._berubah = False
        if os.path.exists(jalur):
            try:
                with open(jalur, encoding="utf-8") as f:
                    data = json.load(f)
                self._entri = dict(data.get("entri", {}))
            except (json.JSONDecodeError, AttributeError, TypeError) as e:
                raise ValueError(f"Berkas baseline tidak valid ({jalur}): {e}") from e

    def ambil(self, kunci: str) -> str | None:
        e = self._entri.get(kunci)
        return e.get("sha256") if e else None

    def set(self, kunci: str, sha256: str) -> None:
        self._entri[kunci] = {
            "sha256": sha256,
            "waktu": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self._berubah = True

    def simpan_jika_berubah(self) -> None:
        if not self._berubah:
            return
        folder = os.path.dirname(os.path.abspath(self.jalur))
        os.makedirs(folder, exist_ok=True)
        fd, sementara = tempfile.mkstemp(dir=folder, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"versi": 1, "entri": self._entri}, f, indent=2, ensure_ascii=False)
            os.replace(sementara, self.jalur)
        except BaseException:
            if os.path.exists(sementara):
                os.remove(sementara)
            raise
        self._berubah = False


def periksa_integritas(
    kunci: str,
    konten: bytes,
    baseline: Baseline,
    terpotong: bool = False,
    simpan: bool = False,
    perbarui: bool = False,
) -> tuple[list[Finding], dict[str, Any]]:
    sekarang = hitung_hash(konten)
    info: dict[str, Any] = {"sha256": sekarang, "ukuran_byte": len(konten), "terpotong": terpotong}
    findings: list[Finding] = []
    lama = baseline.ambil(kunci)

    if lama is None:
        if simpan or perbarui:
            baseline.set(kunci, sekarang)
            info["baseline"] = "DISIMPAN"
            findings.append(Finding(MODUL, "INT_BASELINE_BARU", Level.INFO,
                                    "Baseline baru disimpan", f"SHA-256: {sekarang}"))
        else:
            info["baseline"] = "BELUM_ADA"
            findings.append(Finding(MODUL, "INT_TANPA_BASELINE", Level.INFO,
                                    "Belum ada baseline untuk target ini",
                                    "Jalankan dengan --simpan-baseline untuk merekam hash saat ini."))
    elif lama == sekarang:
        info["baseline"] = "SAMA"
    else:
        info["baseline"] = "BERBEDA"
        info["hash_baseline"] = lama
        findings.append(Finding(
            MODUL, "INT_KONTEN_BERUBAH", Level.MEDIUM,
            "Konten berbeda dari baseline (potensi perubahan/defacement)",
            f"Baseline: {lama}\nSekarang: {sekarang}",
            "Tinjau halaman secara manual. Jika perubahan sah, perbarui baseline (--perbarui-baseline).",
        ))
        if perbarui:
            baseline.set(kunci, sekarang)
            info["baseline"] = "BERBEDA (baseline diperbarui)"
    return findings, info

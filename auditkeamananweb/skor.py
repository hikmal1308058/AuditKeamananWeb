"""MODUL 4: PENILAIAN RISIKO & SKOR."""
from __future__ import annotations

from typing import Iterable

from .models import PENGURANGAN_SKOR, Finding

SKOR_AWAL = 100
BATAS_GRADE = (("A", 85), ("B", 70), ("C", 50))  # di bawah 50 -> D


def hitung_skor(findings: Iterable[Finding]) -> int:
    skor = SKOR_AWAL
    for f in findings:
        skor -= PENGURANGAN_SKOR[f.level]
    return max(0, skor)


def tentukan_grade(skor: int) -> str:
    for grade, batas in BATAS_GRADE:
        if skor >= batas:
            return grade
    return "D"

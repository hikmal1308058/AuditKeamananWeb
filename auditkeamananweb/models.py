"""Model data: temuan (finding) dan hasil audit per target."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Level(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"  # informasi saja, tidak mengurangi skor


# Pengurangan skor per temuan (Modul 4).
PENGURANGAN_SKOR: dict[Level, int] = {
    Level.CRITICAL: 25,
    Level.HIGH: 15,
    Level.MEDIUM: 8,
    Level.LOW: 3,
    Level.INFO: 0,
}

URUTAN_LEVEL: list[Level] = [Level.CRITICAL, Level.HIGH, Level.MEDIUM, Level.LOW, Level.INFO]

# Status hasil per target.
STATUS_OK = "DIPERIKSA"
STATUS_SKIPPED = "SKIPPED (Unauthorized)"
STATUS_NETWORK = "ERROR (Network)"
STATUS_INVALID = "INVALID"
STATUS_INTERNAL = "ERROR (Internal)"


@dataclass
class Finding:
    modul: str
    kode: str
    level: Level
    judul: str
    detail: str = ""
    rekomendasi: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "modul": self.modul,
            "kode": self.kode,
            "level": self.level.value,
            "pengurangan_skor": PENGURANGAN_SKOR[self.level],
            "judul": self.judul,
            "detail": self.detail,
            "rekomendasi": self.rekomendasi,
        }


def _sekarang_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class HasilTarget:
    target: str
    status: str = "BELUM DIPERIKSA"
    hostname: str | None = None
    port: int | None = None
    skema: str | None = None
    path: str | None = None
    skor: int | None = None
    grade: str | None = None
    findings: list[Finding] = field(default_factory=list)
    info: dict[str, Any] = field(default_factory=dict)
    catatan: list[str] = field(default_factory=list)
    waktu_audit: str = field(default_factory=_sekarang_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "status": self.status,
            "hostname": self.hostname,
            "port": self.port,
            "skema": self.skema,
            "path": self.path,
            "skor": self.skor,
            "grade": self.grade,
            "findings": [f.to_dict() for f in self.findings],
            "info": self.info,
            "catatan": self.catatan,
            "waktu_audit": self.waktu_audit,
        }

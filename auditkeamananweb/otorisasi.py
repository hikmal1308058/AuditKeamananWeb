"""Langkah 2b: CEK OTORISASI.

Audit hanya dijalankan pada target yang ada di daftar izin (milik sendiri / izin tertulis)
atau pada domain uji bawaan. Selain itu -> "SKIPPED (Unauthorized)".

Format entri:
  contoh.ac.id        -> hanya host itu
  *.contoh.ac.id      -> semua subdomain (BUKAN apex; tulis apex terpisah bila perlu)
"""
from __future__ import annotations

from typing import Iterable

from .target import baca_daftar

# Domain uji / loopback yang aman diaudit tanpa konfigurasi tambahan.
# badssl.com memang sengaja dibuat untuk menguji klien TLS.
DOMAIN_UJI_BAWAAN: tuple[str, ...] = (
    "localhost",
    "127.0.0.1",
    "::1",
    "example.com",
    "example.org",
    "example.net",
    "badssl.com",
    "*.badssl.com",
)

# Pengaman: wildcard pada sufiks publik umum hampir pasti salah ketik / terlalu luas.
SUFIKS_PUBLIK_UMUM = frozenset(
    {
        "ac.id", "co.id", "go.id", "or.id", "sch.id", "web.id", "my.id", "net.id",
        "mil.id", "desa.id", "biz.id", "ponpes.id", "co.uk", "com.au",
    }
)


class Otorisasi:
    def __init__(self, entri: Iterable[str] = (), sertakan_bawaan: bool = True) -> None:
        self._tepat: set[str] = set()
        self._wildcard: set[str] = set()
        daftar = list(DOMAIN_UJI_BAWAAN) if sertakan_bawaan else []
        daftar += list(entri)
        for e in daftar:
            self.tambah(e)

    def tambah(self, entri: str) -> None:
        e = entri.strip().lower().rstrip(".")
        if not e or e.startswith("#"):
            return
        if e.startswith("*."):
            induk = e[2:]
            if "*" in induk or "." not in induk or induk in SUFIKS_PUBLIK_UMUM:
                raise ValueError(
                    f"Wildcard '{entri}' terlalu luas atau tidak valid. "
                    "Gunakan domain milik Anda, mis. *.kampus-saya.ac.id"
                )
            self._wildcard.add(induk)
        elif "*" in e:
            raise ValueError(f"Wildcard hanya boleh berbentuk '*.domain': {entri!r}")
        else:
            self._tepat.add(e)

    def diizinkan(self, hostname: str) -> bool:
        h = hostname.strip().lower().rstrip(".")
        if h in self._tepat:
            return True
        return any(h.endswith("." + induk) for induk in self._wildcard)

    @classmethod
    def dari_berkas(cls, jalur: Iterable[str], sertakan_bawaan: bool = True) -> "Otorisasi":
        entri: list[str] = []
        for j in jalur:
            entri += baca_daftar(j)
        return cls(entri, sertakan_bawaan=sertakan_bawaan)

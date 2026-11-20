"""Langkah 2a: normalisasi & validasi target -> (skema, hostname, port, path)."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

PORT_BAWAAN = {"http": 80, "https": 443}
_RE_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class TargetTidakValid(ValueError):
    """Target tidak dapat dinormalisasi / divalidasi."""


@dataclass(frozen=True)
class TargetTerurai:
    asli: str
    skema: str
    hostname: str
    port: int
    path: str

    @property
    def netloc(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        if self.port != PORT_BAWAAN[self.skema]:
            return f"{host}:{self.port}"
        return host

    @property
    def url(self) -> str:
        return f"{self.skema}://{self.netloc}{self.path}"


def _adalah_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _hostname_valid(host: str) -> bool:
    if _adalah_ip(host):
        return True
    if not host or len(host) > 253:
        return False
    return all(_RE_LABEL.match(label) for label in host.split("."))


def normalisasi_target(teks: str) -> TargetTerurai:
    """Ubah 'example.com', 'https://example.com:8443/a?b=1' dst. menjadi TargetTerurai.

    Tanpa skema -> https. Port bawaan mengikuti skema. Fragment (#...) dibuang.
    """
    asli = teks
    teks = (teks or "").strip()
    if not teks:
        raise TargetTidakValid("Target kosong")
    if "://" not in teks:
        teks = "https://" + teks

    try:
        bagian = urlsplit(teks)
        port_eksplisit = bagian.port
    except ValueError as e:
        raise TargetTidakValid(f"URL tidak valid: {e}") from e

    skema = bagian.scheme.lower()
    if skema not in PORT_BAWAAN:
        raise TargetTidakValid(f"Skema '{skema}' tidak didukung (hanya http/https)")
    if bagian.username or bagian.password:
        raise TargetTidakValid("Target tidak boleh memuat kredensial (user:pass@)")

    host = (bagian.hostname or "").rstrip(".").lower()
    if not host:
        raise TargetTidakValid("Hostname kosong")
    if not _adalah_ip(host):
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as e:
            raise TargetTidakValid(f"Hostname tidak valid: {e}") from e
    if not _hostname_valid(host):
        raise TargetTidakValid(f"Hostname tidak valid: {host!r}")

    port = port_eksplisit if port_eksplisit is not None else PORT_BAWAAN[skema]
    if not 1 <= port <= 65535:
        raise TargetTidakValid(f"Port di luar jangkauan: {port}")

    path = bagian.path or "/"
    if bagian.query:
        path += "?" + bagian.query

    return TargetTerurai(asli=asli, skema=skema, hostname=host, port=port, path=path)


def baca_daftar(jalur: str) -> list[str]:
    """Baca berkas daftar (satu entri per baris). Baris kosong & komentar (#) diabaikan."""
    hasil: list[str] = []
    with open(jalur, encoding="utf-8-sig") as f:
        for baris in f:
            baris = baris.split(" #", 1)[0].strip()
            if not baris or baris.startswith("#"):
                continue
            hasil.append(baris)
    return hasil

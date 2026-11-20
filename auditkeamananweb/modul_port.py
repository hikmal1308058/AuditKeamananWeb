"""MODUL 6: PINDAI PORT UMUM (opt-in, non-destruktif).

Hanya melakukan TCP connect scan (socket.connect_ex) ke sejumlah kecil port umum pada
hostname target — setara "apakah pintu ini terkunci atau tidak", tanpa mengirim data
apa pun setelah port terbuka. Ini BUKAN pemindai port lengkap (1-65535) atau pemindai
kerentanan layanan; untuk itu pakai alat khusus seperti nmap yang dijalankan terpisah.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass

from .models import Finding, Level

MODUL = "PORT"

# (port, level jika terbuka, nama layanan, alasan)
DAFTAR_PORT_BAWAAN: tuple[tuple[int, Level, str, str], ...] = (
    (21, Level.HIGH, "FTP", "FTP sering mengirim kredensial tanpa enkripsi"),
    (23, Level.HIGH, "Telnet", "Telnet mengirim semua data termasuk password tanpa enkripsi"),
    (25, Level.LOW, "SMTP", "Server mail terbuka ke publik"),
    (135, Level.MEDIUM, "MS-RPC", "RPC Windows biasanya tidak perlu terekspos ke internet"),
    (139, Level.MEDIUM, "NetBIOS", "Berbagi file Windows biasanya tidak perlu terekspos ke internet"),
    (445, Level.HIGH, "SMB", "SMB sering jadi target eksploitasi (mis. ransomware) bila terekspos"),
    (1433, Level.HIGH, "MSSQL", "Database seharusnya tidak dapat diakses langsung dari internet"),
    (1521, Level.HIGH, "Oracle DB", "Database seharusnya tidak dapat diakses langsung dari internet"),
    (3306, Level.HIGH, "MySQL/MariaDB", "Database seharusnya tidak dapat diakses langsung dari internet"),
    (3389, Level.MEDIUM, "RDP", "Remote Desktop yang terekspos jadi target brute-force umum"),
    (5432, Level.HIGH, "PostgreSQL", "Database seharusnya tidak dapat diakses langsung dari internet"),
    (5900, Level.MEDIUM, "VNC", "Remote desktop yang terekspos jadi target brute-force umum"),
    (6379, Level.HIGH, "Redis", "Redis tanpa autentikasi yang terekspos sering disalahgunakan"),
    (9200, Level.HIGH, "Elasticsearch", "Sering terekspos tanpa autentikasi dan membocorkan seluruh data"),
    (27017, Level.HIGH, "MongoDB", "Database seharusnya tidak dapat diakses langsung dari internet"),
)

# Port yang memang menjadi tujuan audit (80/443) sengaja TIDAK dimasukkan daftar di atas,
# karena keberadaannya sudah dicakup Modul 1 & 2, bukan temuan "port tak terduga".
_PORT_TARGET_WAJAR = {80, 443, 8080, 8443}


@dataclass
class HasilPort:
    port: int
    layanan: str


def _port_terbuka(hostname: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except OSError:
        return False


def pindai_port(
    hostname: str,
    timeout: float = 1.5,
    daftar_port: tuple[tuple[int, Level, str, str], ...] = DAFTAR_PORT_BAWAAN,
) -> tuple[list[Finding], dict]:
    """Jalankan Modul 6. Satu percobaan koneksi per port, berurutan."""
    terbuka: list[HasilPort] = []
    for port, _level, layanan, _alasan in daftar_port:
        if port in _PORT_TARGET_WAJAR:
            continue
        if _port_terbuka(hostname, port, timeout):
            terbuka.append(HasilPort(port, layanan))

    findings = [
        Finding(
            MODUL, f"PORT_TERBUKA_{p.port}",
            next(lv for prt, lv, _, _ in daftar_port if prt == p.port),
            f"Port {p.port} ({p.layanan}) terbuka",
            next(al for prt, _, _, al in daftar_port if prt == p.port),
            "Tutup port ini dari akses publik (firewall) kecuali memang harus diakses dari internet; "
            "bila perlu, batasi hanya untuk IP tertentu (allowlist) atau gunakan VPN.",
        )
        for p in terbuka
    ]
    info = {
        "port_diperiksa": len(daftar_port) - len([p for p, *_ in daftar_port if p in _PORT_TARGET_WAJAR]),
        "port_terbuka": [{"port": p.port, "layanan": p.layanan} for p in terbuka],
    }
    return findings, info

"""MODUL 1: TLS & SERTIFIKAT.

Hanya memakai pustaka standar. Untuk membaca tanggal kedaluwarsa dari sertifikat yang
GAGAL diverifikasi (self-signed, hostname salah, dst.) dibutuhkan paket opsional
`cryptography`; tanpanya `sisa_hari` bernilai None pada kasus tersebut.
"""
from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from .models import Finding, Level

MODUL = "TLS"


class GagalKoneksi(Exception):
    """Koneksi TCP ke (hostname, port) gagal."""


# ---------------------------------------------------------------- evaluasi (murni)

PROTOKOL_LEMAH: dict[str, Level] = {
    "SSLv2": Level.CRITICAL,
    "SSLv3": Level.CRITICAL,
    "TLSv1": Level.HIGH,
    "TLSv1.1": Level.HIGH,
}

_RE_CIPHER = re.compile(r"(?:^|[-_])(RC4|3DES|NULL|MD5|ADH|AECDH|ANON)(?:[-_]|$)", re.I)
_LEVEL_CIPHER: dict[str, Level] = {
    "NULL": Level.CRITICAL,
    "ANON": Level.CRITICAL,
    "ADH": Level.CRITICAL,
    "AECDH": Level.CRITICAL,
    "RC4": Level.HIGH,
    "3DES": Level.HIGH,
    "MD5": Level.HIGH,
}


def evaluasi_protokol(versi: str | None) -> list[Finding]:
    """Protokol lemah jika versi < TLS 1.2 (SSLv2/SSLv3/TLS 1.0/TLS 1.1)."""
    if not versi:
        return []
    level = PROTOKOL_LEMAH.get(versi)
    if level is None and versi.upper().startswith("SSL"):
        level = Level.CRITICAL
    if level is None:
        return []
    return [
        Finding(
            MODUL, "TLS_PROTOKOL_LEMAH", level,
            f"Protokol lemah dinegosiasikan: {versi}",
            "Server menerima versi protokol di bawah TLS 1.2.",
            "Nonaktifkan SSLv3/TLS 1.0/TLS 1.1; izinkan hanya TLS 1.2 dan TLS 1.3.",
        )
    ]


def evaluasi_cipher(nama: str | None) -> list[Finding]:
    """Cipher lemah jika mengandung RC4, 3DES, NULL, MD5, atau anonim (ADH/AECDH)."""
    if not nama:
        return []
    komponen = {m.upper() for m in _RE_CIPHER.findall(nama)}
    if "DES-CBC3" in nama.upper():  # penamaan OpenSSL untuk 3DES
        komponen.add("3DES")
    if not komponen:
        return []
    level = max((_LEVEL_CIPHER[k] for k in komponen), key=_peringkat)
    return [
        Finding(
            MODUL, "TLS_CIPHER_LEMAH", level,
            f"Cipher suite lemah: {nama}",
            "Komponen lemah terdeteksi: " + ", ".join(sorted(komponen)) + ".",
            "Pakai cipher modern (AEAD: AES-GCM / ChaCha20-Poly1305) dengan pertukaran kunci ECDHE.",
        )
    ]


def _peringkat(level: Level) -> int:
    return {Level.INFO: 0, Level.LOW: 1, Level.MEDIUM: 2, Level.HIGH: 3, Level.CRITICAL: 4}[level]


def evaluasi_sisa_hari(sisa: int) -> list[Finding]:
    if sisa < 0:
        return [
            Finding(
                MODUL, "TLS_CERT_EXPIRED", Level.CRITICAL, "Sertifikat kedaluwarsa",
                f"Sertifikat sudah kedaluwarsa {-sisa} hari yang lalu.",
                "Perbarui sertifikat dan aktifkan pembaruan otomatis (mis. ACME/Let's Encrypt).",
            )
        ]
    if sisa <= 14:
        level = Level.MEDIUM
    elif sisa <= 30:
        level = Level.LOW
    else:
        return []
    return [
        Finding(
            MODUL, "TLS_CERT_SEGERA_KADALUARSA", level, "Sertifikat segera kedaluwarsa",
            f"Sisa masa berlaku {sisa} hari.",
            "Jadwalkan pembaruan sertifikat sebelum kedaluwarsa.",
        )
    ]


# kode verifikasi OpenSSL -> (kode temuan, level, judul)
_KODE_VERIFIKASI: dict[int, tuple[str, Level, str]] = {
    10: ("TLS_CERT_EXPIRED", Level.CRITICAL, "Sertifikat kedaluwarsa"),
    9: ("TLS_CERT_BELUM_BERLAKU", Level.HIGH, "Sertifikat belum berlaku"),
    18: ("TLS_CERT_SELF_SIGNED", Level.HIGH, "Sertifikat self-signed"),
    19: ("TLS_CERT_SELF_SIGNED", Level.HIGH, "Rantai sertifikat berisi sertifikat self-signed"),
    20: ("TLS_CERT_UNTRUSTED", Level.HIGH, "Sertifikat tidak tepercaya (issuer tidak dikenal)"),
    21: ("TLS_CERT_UNTRUSTED", Level.HIGH, "Sertifikat tidak tepercaya (rantai tidak lengkap)"),
    62: ("TLS_HOSTNAME_MISMATCH", Level.HIGH, "Hostname tidak cocok dengan sertifikat"),
    64: ("TLS_HOSTNAME_MISMATCH", Level.HIGH, "Alamat IP tidak cocok dengan sertifikat"),
}


def evaluasi_error_verifikasi(kode: int | None, pesan: str | None) -> list[Finding]:
    kode_temuan, level, judul = _KODE_VERIFIKASI.get(
        kode or -1,
        ("TLS_CERT_UNTRUSTED", Level.HIGH, "Sertifikat gagal diverifikasi"),
    )
    return [
        Finding(
            MODUL, kode_temuan, level, judul,
            f"Pesan verifikasi: {pesan or '-'} (kode OpenSSL {kode}).",
            "Gunakan sertifikat dari CA tepercaya yang mencakup hostname ini dan rantai yang lengkap.",
        )
    ]


# ---------------------------------------------------------------- akses jaringan

def uji_koneksi_tcp(hostname: str, port: int, timeout: float) -> socket.socket:
    try:
        return socket.create_connection((hostname, port), timeout=timeout)
    except OSError as e:
        raise GagalKoneksi(f"{type(e).__name__}: {e}") from e


def _catat_sesi(ssock: ssl.SSLSocket, info: dict[str, Any]) -> None:
    info["protokol"] = ssock.version()
    cipher = ssock.cipher()
    if cipher:
        info["cipher_suite"] = cipher[0]
        info["bit_cipher"] = cipher[2]


def _nama_dari_rdn(rdn: Any) -> str | None:
    d: dict[str, str] = {}
    for item in rdn or ():
        for k, v in item:
            d[k] = v
    return d.get("commonName") or d.get("organizationName")


def _kedaluwarsa_dari_dict(cert: dict[str, Any]) -> datetime | None:
    na = cert.get("notAfter")
    if not na:
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(na), timezone.utc)


def _kedaluwarsa_dari_der(der: bytes | None) -> datetime | None:
    if not der:
        return None
    try:
        from cryptography import x509  # paket opsional
    except ImportError:
        return None
    try:
        sert = x509.load_der_x509_certificate(der)
        if hasattr(sert, "not_valid_after_utc"):
            return sert.not_valid_after_utc
        return sert.not_valid_after.replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001 - sertifikat tidak terbaca, abaikan
        return None


def _sambung_permisif(hostname: str, port: int, timeout: float):
    """Handshake tanpa verifikasi & dengan protokol/cipher lama diizinkan.

    Dipakai (1) mengambil info sesi dari sertifikat yang gagal verifikasi, dan
    (2) mendeteksi server legasi yang tidak bisa dihubungi klien modern.
    """
    sock = uji_koneksi_tcp(hostname, port, timeout)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        pass  # build OpenSSL tidak mengizinkan; pakai pengaturan bawaan
    with ctx.wrap_socket(sock, server_hostname=hostname) as s:
        return s.version(), s.cipher(), s.getpeercert(binary_form=True)


def _tanpa_duplikat(findings: list[Finding]) -> list[Finding]:
    terlihat: set[str] = set()
    hasil: list[Finding] = []
    for f in findings:
        if f.kode in terlihat:
            continue
        terlihat.add(f.kode)
        hasil.append(f)
    return hasil


def periksa_tls(
    hostname: str,
    port: int,
    timeout: float = 8.0,
    sekarang: datetime | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    """Jalankan Modul 1. Melempar GagalKoneksi bila koneksi TCP gagal."""
    sekarang = sekarang or datetime.now(timezone.utc)
    findings: list[Finding] = []
    info: dict[str, Any] = {}
    kedaluwarsa: datetime | None = None
    perlu_permisif = False
    galat_primer: Exception | None = None

    sock = uji_koneksi_tcp(hostname, port, timeout)  # GagalKoneksi dibiarkan naik

    try:
        with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as ssock:
            _catat_sesi(ssock, info)
            cert = ssock.getpeercert() or {}
            info["subjek"] = _nama_dari_rdn(cert.get("subject"))
            info["penerbit"] = _nama_dari_rdn(cert.get("issuer"))
            kedaluwarsa = _kedaluwarsa_dari_dict(cert)
        info["verifikasi_sertifikat"] = "OK"
    except ssl.SSLCertVerificationError as e:
        info["verifikasi_sertifikat"] = f"GAGAL: {e.verify_message}"
        findings += evaluasi_error_verifikasi(e.verify_code, e.verify_message)
        perlu_permisif = True
    except (ssl.SSLError, OSError) as e:
        galat_primer = e
        perlu_permisif = True

    if perlu_permisif:
        try:
            versi, cipher, der = _sambung_permisif(hostname, port, timeout)
        except (GagalKoneksi, OSError) as e2:
            if galat_primer is not None:
                findings.append(
                    Finding(
                        MODUL, "TLS_HANDSHAKE_GAGAL", Level.HIGH, "Handshake TLS gagal",
                        f"{type(galat_primer).__name__}: {galat_primer}",
                        "Pastikan port melayani TLS dengan konfigurasi yang valid.",
                    )
                )
                info["error_handshake"] = str(galat_primer)
                return _tanpa_duplikat(findings), info
            info["catatan_tls"] = f"Info sesi tidak dapat diambil ulang: {e2}"
        else:
            info["protokol"] = versi
            if cipher:
                info["cipher_suite"] = cipher[0]
                info["bit_cipher"] = cipher[2]
            kedaluwarsa = kedaluwarsa or _kedaluwarsa_dari_der(der)
            if galat_primer is not None:
                info["verifikasi_sertifikat"] = "TIDAK DIVERIFIKASI (handshake normal gagal)"
                findings.append(
                    Finding(
                        MODUL, "TLS_HANDSHAKE_LEGASI", Level.INFO,
                        "Handshake hanya berhasil dengan konfigurasi TLS longgar",
                        f"Klien modern gagal: {galat_primer}",
                    )
                )

    findings += evaluasi_protokol(info.get("protokol"))
    findings += evaluasi_cipher(info.get("cipher_suite"))

    if kedaluwarsa is not None:
        sisa = (kedaluwarsa - sekarang).days
        info["tanggal_kadaluarsa"] = kedaluwarsa.isoformat()
        info["sisa_hari"] = sisa
        findings += evaluasi_sisa_hari(sisa)
    else:
        info["sisa_hari"] = None

    return _tanpa_duplikat(findings), info

"""MODUL 2: HTTP HEADERS & COOKIE.

Mengirim satu permintaan GET biasa (bukan serangan), mengikuti redirect maksimal R kali,
dan hanya mengikuti redirect ke host yang juga diotorisasi.
"""
from __future__ import annotations

import http.client
import re
import ssl
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin

from .models import Finding, Level
from .target import TargetTerurai, TargetTidakValid, normalisasi_target

MODUL = "HTTP"
USER_AGENT = "AuditKeamananWeb/1.0 (audit terotorisasi)"
MAKS_BODY = 2 * 1024 * 1024  # 2 MiB
KODE_REDIRECT = {301, 302, 303, 307, 308}
HSTS_MIN_DETIK = 15_552_000  # 180 hari


@dataclass
class ResponHTTP:
    url_akhir: str
    skema_akhir: str
    status: int
    alasan: str
    header: dict[str, str]  # kunci huruf kecil
    cookies: list[str]  # nilai mentah Set-Cookie
    body: bytes
    terpotong: bool
    rantai_redirect: list[str] = field(default_factory=list)
    catatan: list[str] = field(default_factory=list)


def _konteks_tanpa_verifikasi() -> ssl.SSLContext:
    # Validitas sertifikat sudah dilaporkan Modul 1; di sini tujuannya hanya membaca header.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def ambil_respons(
    target: TargetTerurai,
    timeout: float = 8.0,
    maks_redirect: int = 5,
    diizinkan: Callable[[str], bool] = lambda host: True,
    maks_body: int = MAKS_BODY,
) -> ResponHTTP:
    saat_ini = target
    rantai: list[str] = []
    catatan: list[str] = []
    ctx = _konteks_tanpa_verifikasi()

    while True:
        if saat_ini.skema == "https":
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                saat_ini.hostname, saat_ini.port, timeout=timeout, context=ctx
            )
        else:
            conn = http.client.HTTPConnection(saat_ini.hostname, saat_ini.port, timeout=timeout)
        try:
            conn.request(
                "GET",
                saat_ini.path,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                    "Connection": "close",
                },
            )
            resp = conn.getresponse()
            pasangan = resp.getheaders()
            body = resp.read(maks_body + 1)
            status, alasan = resp.status, resp.reason
        finally:
            conn.close()
        rantai.append(saat_ini.url)

        if status in KODE_REDIRECT:
            lokasi = next((v for k, v in pasangan if k.lower() == "location"), None)
            if lokasi:
                if len(rantai) > maks_redirect:
                    catatan.append(f"Batas redirect ({maks_redirect}) tercapai; redirect tidak diikuti.")
                    break
                try:
                    berikut = normalisasi_target(urljoin(saat_ini.url, lokasi))
                except TargetTidakValid as e:
                    catatan.append(f"Lokasi redirect tidak valid, tidak diikuti: {e}")
                    break
                if not diizinkan(berikut.hostname):
                    catatan.append(
                        f"Redirect ke host yang tidak diotorisasi ({berikut.hostname}) tidak diikuti."
                    )
                    break
                saat_ini = berikut
                continue
        break

    header: dict[str, str] = {}
    cookies: list[str] = []
    for k, v in pasangan:
        kl = k.lower()
        if kl == "set-cookie":
            cookies.append(v)
        elif kl in header:
            header[kl] += ", " + v
        else:
            header[kl] = v

    terpotong = len(body) > maks_body
    return ResponHTTP(
        url_akhir=saat_ini.url,
        skema_akhir=saat_ini.skema,
        status=status,
        alasan=alasan,
        header=header,
        cookies=cookies,
        body=body[:maks_body],
        terpotong=terpotong,
        rantai_redirect=rantai,
        catatan=catatan,
    )


# ---------------------------------------------------------------- evaluasi (murni)

def evaluasi_header(header: dict[str, str], https: bool) -> list[Finding]:
    h = {k.lower(): v for k, v in header.items()}
    f: list[Finding] = []

    # HSTS (hanya bermakna lewat HTTPS)
    if https:
        hsts = h.get("strict-transport-security")
        if hsts is None:
            f.append(Finding(
                MODUL, "HDR_HSTS_HILANG", Level.MEDIUM, "Header HSTS tidak ada",
                "Browser tidak dipaksa memakai HTTPS (rentan downgrade/SSL stripping).",
                "Strict-Transport-Security: max-age=31536000; includeSubDomains",
            ))
        else:
            m = re.search(r'max-age\s*=\s*"?(\d+)"?', hsts, re.I)
            if not m or int(m.group(1)) == 0:
                f.append(Finding(
                    MODUL, "HDR_HSTS_TIDAK_VALID", Level.MEDIUM, "HSTS tidak valid atau max-age=0",
                    f"Nilai: {hsts}",
                    "Setel max-age minimal 15552000 (180 hari); idealnya 31536000.",
                ))
            elif int(m.group(1)) < HSTS_MIN_DETIK:
                f.append(Finding(
                    MODUL, "HDR_HSTS_PENDEK", Level.LOW, "HSTS max-age terlalu pendek",
                    f"max-age={m.group(1)} detik (< {HSTS_MIN_DETIK}).",
                    "Naikkan max-age menjadi minimal 15552000, idealnya 31536000.",
                ))

    # CSP
    csp = h.get("content-security-policy")
    if csp is None:
        f.append(Finding(
            MODUL, "HDR_CSP_HILANG", Level.MEDIUM, "Content-Security-Policy tidak ada",
            "Tanpa CSP, dampak XSS/injeksi konten lebih besar.",
            "Mulai dari CSP ketat, mis. default-src 'self'; lalu longgarkan seperlunya.",
        ))
    elif re.search(r"'unsafe-(inline|eval)'", csp, re.I):
        f.append(Finding(
            MODUL, "HDR_CSP_LEMAH", Level.LOW, "CSP mengizinkan 'unsafe-inline' / 'unsafe-eval'",
            f"Nilai: {csp[:200]}",
            "Gunakan nonce atau hash alih-alih 'unsafe-inline'/'unsafe-eval'.",
        ))

    # Anti-clickjacking: X-Frame-Options atau CSP frame-ancestors
    xfo = h.get("x-frame-options", "").strip().lower()
    xfo_ok = xfo in ("deny", "sameorigin") or xfo.startswith("allow-from")
    fa_ok = bool(csp and re.search(r"(?:^|;)\s*frame-ancestors\s", csp, re.I))
    if not (xfo_ok or fa_ok):
        f.append(Finding(
            MODUL, "HDR_ANTI_CLICKJACKING_HILANG", Level.MEDIUM,
            "Perlindungan clickjacking tidak ada",
            "Tidak ada X-Frame-Options maupun CSP frame-ancestors yang valid.",
            "Tambahkan Content-Security-Policy: frame-ancestors 'self' (atau X-Frame-Options: SAMEORIGIN).",
        ))

    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        f.append(Finding(
            MODUL, "HDR_NOSNIFF_HILANG", Level.LOW, "X-Content-Type-Options: nosniff tidak ada",
            "Browser boleh menebak MIME type (MIME sniffing).",
            "X-Content-Type-Options: nosniff",
        ))

    if "referrer-policy" not in h:
        f.append(Finding(
            MODUL, "HDR_REFERRER_POLICY_HILANG", Level.LOW, "Referrer-Policy tidak ada",
            "URL halaman bisa bocor lewat header Referer ke situs lain.",
            "Referrer-Policy: strict-origin-when-cross-origin",
        ))

    if "permissions-policy" not in h:
        f.append(Finding(
            MODUL, "HDR_PERMISSIONS_POLICY_HILANG", Level.LOW, "Permissions-Policy tidak ada",
            "Fitur browser (kamera, mikrofon, geolokasi, dst.) tidak dibatasi eksplisit.",
            "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        ))

    return f


def parse_cookie(mentah: str) -> dict:
    bagian = [b.strip() for b in mentah.split(";")]
    nama = bagian[0].split("=", 1)[0].strip() or "(tanpa-nama)"
    flags: set[str] = set()
    samesite: str | None = None
    for attr in bagian[1:]:
        kunci, _, nilai = attr.partition("=")
        kunci = kunci.strip().lower()
        if kunci == "samesite":
            samesite = nilai.strip().lower()
        elif kunci:
            flags.add(kunci)
    return {
        "nama": nama,
        "secure": "secure" in flags,
        "httponly": "httponly" in flags,
        "samesite": samesite,
    }


def evaluasi_cookie(cookies: list[str], https: bool) -> list[Finding]:
    """Satu temuan per JENIS masalah (nama cookie digabung) agar skor tidak melonjak
    hanya karena banyaknya cookie. Nilai cookie tidak pernah dicatat."""
    tanpa_secure: list[str] = []
    tanpa_httponly: list[str] = []
    tanpa_samesite: list[str] = []
    none_tanpa_secure: list[str] = []

    for mentah in cookies:
        c = parse_cookie(mentah)
        if https and not c["secure"]:
            tanpa_secure.append(c["nama"])
        if not c["httponly"]:
            tanpa_httponly.append(c["nama"])
        if c["samesite"] is None:
            tanpa_samesite.append(c["nama"])
        elif c["samesite"] == "none" and not c["secure"]:
            none_tanpa_secure.append(c["nama"])

    f: list[Finding] = []
    if tanpa_secure:
        f.append(Finding(
            MODUL, "COOKIE_TANPA_SECURE", Level.MEDIUM, "Cookie tanpa flag Secure",
            "Cookie: " + ", ".join(tanpa_secure),
            "Tambahkan atribut Secure agar cookie hanya dikirim lewat HTTPS.",
        ))
    if tanpa_httponly:
        f.append(Finding(
            MODUL, "COOKIE_TANPA_HTTPONLY", Level.MEDIUM, "Cookie tanpa flag HttpOnly",
            "Cookie: " + ", ".join(tanpa_httponly),
            "Tambahkan HttpOnly pada cookie yang tidak perlu dibaca JavaScript (mis. sesi).",
        ))
    if tanpa_samesite:
        f.append(Finding(
            MODUL, "COOKIE_TANPA_SAMESITE", Level.LOW, "Cookie tanpa atribut SameSite",
            "Cookie: " + ", ".join(tanpa_samesite),
            "Setel SameSite=Lax (atau Strict) untuk mengurangi risiko CSRF.",
        ))
    if none_tanpa_secure:
        f.append(Finding(
            MODUL, "COOKIE_SAMESITE_NONE_TANPA_SECURE", Level.MEDIUM,
            "Cookie SameSite=None tanpa Secure",
            "Cookie: " + ", ".join(none_tanpa_secure),
            "SameSite=None wajib dipasangkan dengan Secure.",
        ))
    return f


_RE_VERSI = re.compile(r"\d+\.\d+|/\d")


def evaluasi_banner(header: dict[str, str]) -> list[Finding]:
    h = {k.lower(): v for k, v in header.items()}
    terbuka: list[str] = []
    server = h.get("server")
    if server and _RE_VERSI.search(server):
        terbuka.append(f"Server: {server}")
    for nama in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if nama in h:
            terbuka.append(f"{nama}: {h[nama]}")
    if not terbuka:
        return []
    return [Finding(
        MODUL, "BANNER_TERBUKA", Level.LOW, "Banner server membuka versi/teknologi",
        "; ".join(terbuka),
        "Sembunyikan versi (mis. server_tokens off / ServerTokens Prod) dan hapus X-Powered-By.",
    )]


def evaluasi_respons(respons: ResponHTTP) -> list[Finding]:
    https = respons.skema_akhir == "https"
    f = evaluasi_header(respons.header, https)
    f += evaluasi_cookie(respons.cookies, https)
    f += evaluasi_banner(respons.header)
    if respons.rantai_redirect and respons.rantai_redirect[0].startswith("https://") and not https:
        f.append(Finding(
            MODUL, "HTTP_DOWNGRADE_REDIRECT", Level.HIGH, "Redirect menurunkan koneksi dari HTTPS ke HTTP",
            " -> ".join(respons.rantai_redirect),
            "Pastikan redirect selalu menuju HTTPS.",
        ))
    return f

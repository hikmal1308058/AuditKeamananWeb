import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from auditkeamananweb import Baseline, KonfigAudit, Level, Otorisasi, audit_keamanan_web
from auditkeamananweb.laporan import format_teks, ke_json
from auditkeamananweb.modul_cve import cocokkan_versi
from auditkeamananweb.modul_eksposur import DAFTAR_PATH_BAWAAN, periksa_eksposur
from auditkeamananweb.modul_http import (
    ResponHTTP, evaluasi_banner, evaluasi_cookie, evaluasi_header, evaluasi_respons, parse_cookie,
)
from auditkeamananweb.modul_integritas import hitung_hash, periksa_integritas
from auditkeamananweb.modul_port import pindai_port
from auditkeamananweb.modul_tls import (
    evaluasi_cipher, evaluasi_error_verifikasi, evaluasi_protokol, evaluasi_sisa_hari,
)
from auditkeamananweb.models import Finding
from auditkeamananweb.skor import hitung_skor, tentukan_grade
from auditkeamananweb.target import TargetTidakValid, normalisasi_target

HEADER_LENGKAP = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


def kode(findings):
    return {f.kode for f in findings}


class TestTarget(unittest.TestCase):
    def test_domain_polos_menjadi_https(self):
        t = normalisasi_target("Example.COM")
        self.assertEqual((t.skema, t.hostname, t.port, t.path), ("https", "example.com", 443, "/"))

    def test_url_lengkap(self):
        t = normalisasi_target("http://sub.example.com:8080/a/b?x=1#frag")
        self.assertEqual((t.skema, t.hostname, t.port, t.path), ("http", "sub.example.com", 8080, "/a/b?x=1"))
        self.assertEqual(t.url, "http://sub.example.com:8080/a/b?x=1")

    def test_ipv6(self):
        t = normalisasi_target("https://[::1]:8443/")
        self.assertEqual((t.hostname, t.port), ("::1", 8443))
        self.assertEqual(t.netloc, "[::1]:8443")

    def test_idn(self):
        self.assertEqual(normalisasi_target("bücher.example").hostname, "xn--bcher-kva.example")

    def test_tidak_valid(self):
        for buruk in ["", "   ", "ftp://x.com", "http://u:p@x.com", "bad host!", "https://x.com:99999", "a..b"]:
            with self.subTest(buruk=buruk):
                with self.assertRaises(TargetTidakValid):
                    normalisasi_target(buruk)


class TestOtorisasi(unittest.TestCase):
    def test_bawaan(self):
        o = Otorisasi()
        self.assertTrue(o.diizinkan("localhost"))
        self.assertTrue(o.diizinkan("127.0.0.1"))
        self.assertTrue(o.diizinkan("expired.badssl.com"))
        self.assertTrue(o.diizinkan("badssl.com"))
        self.assertFalse(o.diizinkan("google.com"))

    def test_tanpa_bawaan(self):
        self.assertFalse(Otorisasi(sertakan_bawaan=False).diizinkan("localhost"))

    def test_wildcard_tidak_mencakup_apex(self):
        o = Otorisasi(["*.kampus.ac.id"], sertakan_bawaan=False)
        self.assertTrue(o.diizinkan("sim.kampus.ac.id"))
        self.assertFalse(o.diizinkan("kampus.ac.id"))
        self.assertFalse(o.diizinkan("evilkampus.ac.id"))

    def test_wildcard_terlalu_luas_ditolak(self):
        for buruk in ["*", "*.com", "*.ac.id", "*.co.id", "a*.com"]:
            with self.subTest(buruk=buruk):
                with self.assertRaises(ValueError):
                    Otorisasi([buruk])


class TestEvaluasiTLS(unittest.TestCase):
    def test_protokol(self):
        self.assertEqual(kode(evaluasi_protokol("TLSv1.3")), set())
        self.assertEqual(kode(evaluasi_protokol("TLSv1.2")), set())
        self.assertEqual(evaluasi_protokol("TLSv1.1")[0].level, Level.HIGH)
        self.assertEqual(evaluasi_protokol("TLSv1")[0].level, Level.HIGH)
        self.assertEqual(evaluasi_protokol("SSLv3")[0].level, Level.CRITICAL)

    def test_cipher_lemah(self):
        kasus = {
            "ECDHE-RSA-AES128-GCM-SHA256": None,
            "TLS_AES_256_GCM_SHA384": None,
            "RC4-SHA": Level.HIGH,
            "TLS_RSA_WITH_RC4_128_MD5": Level.HIGH,
            "DES-CBC3-SHA": Level.HIGH,
            "ECDHE-RSA-DES-CBC3-SHA": Level.HIGH,
            "NULL-SHA": Level.CRITICAL,
            "ADH-AES128-SHA": Level.CRITICAL,
            "AECDH-AES256-SHA": Level.CRITICAL,
        }
        for nama, level in kasus.items():
            with self.subTest(nama=nama):
                hasil = evaluasi_cipher(nama)
                if level is None:
                    self.assertEqual(hasil, [])
                else:
                    self.assertEqual(len(hasil), 1)
                    self.assertEqual(hasil[0].level, level)

    def test_sisa_hari(self):
        self.assertEqual(evaluasi_sisa_hari(90), [])
        self.assertEqual(evaluasi_sisa_hari(31), [])
        self.assertEqual(evaluasi_sisa_hari(30)[0].level, Level.LOW)
        self.assertEqual(evaluasi_sisa_hari(14)[0].level, Level.MEDIUM)
        self.assertEqual(evaluasi_sisa_hari(0)[0].level, Level.MEDIUM)
        self.assertEqual(evaluasi_sisa_hari(-1)[0].kode, "TLS_CERT_EXPIRED")

    def test_kode_verifikasi(self):
        self.assertEqual(evaluasi_error_verifikasi(10, "expired")[0].kode, "TLS_CERT_EXPIRED")
        self.assertEqual(evaluasi_error_verifikasi(18, "self signed")[0].kode, "TLS_CERT_SELF_SIGNED")
        self.assertEqual(evaluasi_error_verifikasi(62, "mismatch")[0].kode, "TLS_HOSTNAME_MISMATCH")
        self.assertEqual(evaluasi_error_verifikasi(20, "issuer")[0].kode, "TLS_CERT_UNTRUSTED")
        self.assertEqual(evaluasi_error_verifikasi(999, "?")[0].kode, "TLS_CERT_UNTRUSTED")


class TestEvaluasiHTTP(unittest.TestCase):
    def test_header_lengkap_bersih(self):
        self.assertEqual(evaluasi_header(HEADER_LENGKAP, https=True), [])

    def test_header_kosong(self):
        k = kode(evaluasi_header({}, https=True))
        self.assertEqual(k, {
            "HDR_HSTS_HILANG", "HDR_CSP_HILANG", "HDR_ANTI_CLICKJACKING_HILANG", "HDR_NOSNIFF_HILANG",
            "HDR_REFERRER_POLICY_HILANG", "HDR_PERMISSIONS_POLICY_HILANG",
        })

    def test_http_biasa_tidak_menuntut_hsts(self):
        self.assertNotIn("HDR_HSTS_HILANG", kode(evaluasi_header({}, https=False)))

    def test_hsts(self):
        dasar = dict(HEADER_LENGKAP)
        dasar["Strict-Transport-Security"] = "max-age=300"
        self.assertEqual(kode(evaluasi_header(dasar, True)), {"HDR_HSTS_PENDEK"})
        dasar["Strict-Transport-Security"] = "max-age=0"
        self.assertEqual(kode(evaluasi_header(dasar, True)), {"HDR_HSTS_TIDAK_VALID"})
        dasar["Strict-Transport-Security"] = "includeSubDomains"
        self.assertEqual(kode(evaluasi_header(dasar, True)), {"HDR_HSTS_TIDAK_VALID"})

    def test_csp_unsafe_dan_xfo(self):
        dasar = dict(HEADER_LENGKAP)
        dasar["Content-Security-Policy"] = "script-src 'self' 'unsafe-inline'"
        self.assertEqual(kode(evaluasi_header(dasar, True)), {"HDR_CSP_LEMAH", "HDR_ANTI_CLICKJACKING_HILANG"})
        dasar["X-Frame-Options"] = "SAMEORIGIN"
        self.assertEqual(kode(evaluasi_header(dasar, True)), {"HDR_CSP_LEMAH"})

    def test_parse_cookie(self):
        c = parse_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(c, {"nama": "sid", "secure": True, "httponly": True, "samesite": "lax"})

    def test_cookie(self):
        self.assertEqual(evaluasi_cookie(["a=1; Secure; HttpOnly; SameSite=Strict"], True), [])
        k = kode(evaluasi_cookie(["a=1", "b=2; Secure"], True))
        self.assertEqual(k, {"COOKIE_TANPA_SECURE", "COOKIE_TANPA_HTTPONLY", "COOKIE_TANPA_SAMESITE"})
        self.assertEqual(
            kode(evaluasi_cookie(["a=1; HttpOnly; SameSite=None"], True)),
            {"COOKIE_TANPA_SECURE", "COOKIE_SAMESITE_NONE_TANPA_SECURE"},
        )

    def test_cookie_digabung_dan_nilai_tidak_bocor(self):
        hasil = evaluasi_cookie(["a=RAHASIA1", "b=RAHASIA2", "c=RAHASIA3"], True)
        self.assertEqual(len(hasil), 3)  # secure, httponly, samesite: masing-masing satu temuan
        semua = " ".join(f.detail for f in hasil)
        self.assertNotIn("RAHASIA", semua)
        self.assertIn("a, b, c", semua)

    def test_banner(self):
        self.assertEqual(evaluasi_banner({"Server": "nginx"}), [])
        self.assertEqual(evaluasi_banner({"Server": "cloudflare"}), [])
        self.assertEqual(kode(evaluasi_banner({"Server": "Apache/2.4.58"})), {"BANNER_TERBUKA"})
        self.assertEqual(kode(evaluasi_banner({"X-Powered-By": "PHP/8.2"})), {"BANNER_TERBUKA"})

    def test_downgrade_redirect(self):
        r = ResponHTTP("http://x.com/", "http", 200, "OK", dict(HEADER_LENGKAP), [], b"", False,
                       ["https://x.com/", "http://x.com/"])
        self.assertIn("HTTP_DOWNGRADE_REDIRECT", kode(evaluasi_respons(r)))


class TestSkor(unittest.TestCase):
    def _f(self, *levels):
        return [Finding("T", f"K{i}", lv, "j") for i, lv in enumerate(levels)]

    def test_hitung(self):
        self.assertEqual(hitung_skor([]), 100)
        self.assertEqual(hitung_skor(self._f(Level.CRITICAL, Level.HIGH, Level.MEDIUM, Level.LOW)), 100 - 25 - 15 - 8 - 3)
        self.assertEqual(hitung_skor(self._f(Level.INFO, Level.INFO)), 100)

    def test_batas_minimum_nol(self):
        self.assertEqual(hitung_skor(self._f(*[Level.CRITICAL] * 6)), 0)

    def test_grade(self):
        for skor, grade in [(100, "A"), (85, "A"), (84, "B"), (70, "B"), (69, "C"), (50, "C"), (49, "D"), (0, "D")]:
            with self.subTest(skor=skor):
                self.assertEqual(tentukan_grade(skor), grade)


class TestIntegritas(unittest.TestCase):
    def test_sha256(self):
        self.assertEqual(hitung_hash(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_alur_baseline(self):
        with tempfile.TemporaryDirectory() as d:
            jalur = os.path.join(d, "sub", "baseline.json")
            b = Baseline(jalur)
            f, _ = periksa_integritas("u", b"v1", b)
            self.assertEqual(kode(f), {"INT_TANPA_BASELINE"})
            f, _ = periksa_integritas("u", b"v1", b, simpan=True)
            self.assertEqual(kode(f), {"INT_BASELINE_BARU"})
            b.simpan_jika_berubah()

            b2 = Baseline(jalur)  # dimuat ulang dari disk
            f, info = periksa_integritas("u", b"v1", b2)
            self.assertEqual((f, info["baseline"]), ([], "SAMA"))
            f, info = periksa_integritas("u", b"v2", b2)
            self.assertEqual(kode(f), {"INT_KONTEN_BERUBAH"})
            self.assertEqual(b2.ambil("u"), hitung_hash(b"v1"))  # tidak ditimpa tanpa --perbarui
            periksa_integritas("u", b"v2", b2, perbarui=True)
            self.assertEqual(b2.ambil("u"), hitung_hash(b"v2"))

    def test_baseline_rusak(self):
        with tempfile.TemporaryDirectory() as d:
            jalur = os.path.join(d, "b.json")
            with open(jalur, "w") as f:
                f.write("{bukan json")
            with self.assertRaises(ValueError):
                Baseline(jalur)


class TestModulCVE(unittest.TestCase):
    def test_apache_rentan(self):
        self.assertEqual(kode(cocokkan_versi("Apache/2.4.49 (Unix)")), {"CVE_VERSI_BERPOTENSI_RENTAN"})
        self.assertEqual(cocokkan_versi("Apache/2.4.49 (Unix)")[0].level, Level.CRITICAL)

    def test_apache_terbaru_aman(self):
        self.assertEqual(cocokkan_versi("Apache/2.4.58 (Unix)"), [])

    def test_nginx_lama_vs_baru(self):
        self.assertEqual(kode(cocokkan_versi("nginx/1.14.0")), {"CVE_VERSI_BERPOTENSI_RENTAN"})
        self.assertEqual(cocokkan_versi("nginx/1.20.0"), [])

    def test_php_eol(self):
        self.assertEqual(kode(cocokkan_versi("PHP/5.6.39")), {"CVE_VERSI_BERPOTENSI_RENTAN"})
        self.assertEqual(kode(cocokkan_versi("PHP/7.1.33")), {"CVE_VERSI_BERPOTENSI_RENTAN"})
        self.assertEqual(cocokkan_versi("PHP/5.6.40"), [])  # versi batas, sudah dianggap patched
        self.assertEqual(cocokkan_versi("PHP/8.1.0"), [])

    def test_banner_kosong_atau_tak_dikenal(self):
        self.assertEqual(cocokkan_versi(""), [])
        self.assertEqual(cocokkan_versi("cloudflare"), [])

    def test_nilai_tidak_pernah_crash_pada_versi_aneh(self):
        for aneh in ["Apache", "Apache/", "Apache/abc", "nginx/1", "PHP/5"]:
            with self.subTest(aneh=aneh):
                cocokkan_versi(aneh)  # tidak boleh melempar exception


class TestModulEksposur(unittest.TestCase):
    """Server uji hanya membalas 200 utk /.env, selain itu 404 - memastikan modul
    benar-benar membedakan path yang ADA dari yang tidak, bukan menandai semuanya."""

    @classmethod
    def setUpClass(cls):
        class _HandlerEksposur(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/.env":
                    body = b"DB_PASSWORD=rahasia"
                    self.send_response(200)
                elif self.path == "/server-status":
                    body = b"forbidden"
                    self.send_response(403)
                else:
                    body = b"not found"
                    self.send_response(404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        cls.srv, cls.port = _mulai_server(handler_cls=_HandlerEksposur)

    @classmethod
    def tearDownClass(cls):
        _hentikan(cls.srv)

    def test_hanya_path_yang_ada_dilaporkan(self):
        t = normalisasi_target(f"http://127.0.0.1:{self.port}/")
        findings, info = periksa_eksposur(t, timeout=3)
        self.assertEqual(info["path_diperiksa"], len(DAFTAR_PATH_BAWAAN))
        path_ditemukan = {p["path"] for p in info["path_terekspos"]}
        self.assertEqual(path_ditemukan, {"/.env", "/server-status"})
        temuan_env = next(f for f in findings if "/.env" in f.judul)
        self.assertEqual(temuan_env.level, Level.CRITICAL)
        # nilai isi berkas tidak pernah ikut tercatat
        self.assertNotIn("rahasia", " ".join(f.detail for f in findings))
        self.assertEqual(info["path_disaring_pola_generik"], [])


class TestModulEksposurPolaGenerik(unittest.TestCase):
    """Server yang membalas 403 untuk SEMUA path (termasuk yang jelas tidak ada) tidak boleh
    membuat seluruh daftar path sensitif dilaporkan sebagai 'terekspos' -- itu kasus nyata
    yang pernah terjadi (WAF/aturan blanket pada situs pemerintah), bukan bukti kebocoran."""

    @classmethod
    def setUpClass(cls):
        class _HandlerBlanket403(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"Forbidden"
                self.send_response(403)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        cls.srv, cls.port = _mulai_server(handler_cls=_HandlerBlanket403)

    @classmethod
    def tearDownClass(cls):
        _hentikan(cls.srv)

    def test_semua_403_identik_disaring(self):
        t = normalisasi_target(f"http://127.0.0.1:{self.port}/")
        findings, info = periksa_eksposur(t, timeout=3)
        self.assertEqual(info["path_terekspos"], [])  # tidak ada yang dilaporkan sebagai eksposur
        self.assertEqual(len(info["path_disaring_pola_generik"]), len(DAFTAR_PATH_BAWAAN))
        self.assertEqual(info["status_kontrol"], 403)
        self.assertEqual(kode(findings), {"EKSPOSUR_POLA_GENERIK_TERDETEKSI"})
        self.assertEqual(findings[0].level, Level.INFO)


class TestModulEksposurCatchAll200(unittest.TestCase):
    """Server gaya SPA yang selalu membalas 200 dengan isi index.html yang sama persis,
    apa pun path-nya, juga tidak boleh dianggap 'semua path sensitif ditemukan'."""

    @classmethod
    def setUpClass(cls):
        class _HandlerCatchAll(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"<html>index SPA</html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        cls.srv, cls.port = _mulai_server(handler_cls=_HandlerCatchAll)

    @classmethod
    def tearDownClass(cls):
        _hentikan(cls.srv)

    def test_isi_identik_disaring_meski_status_200(self):
        t = normalisasi_target(f"http://127.0.0.1:{self.port}/")
        findings, info = periksa_eksposur(t, timeout=3)
        self.assertEqual(info["path_terekspos"], [])
        self.assertEqual(len(info["path_disaring_pola_generik"]), len(DAFTAR_PATH_BAWAAN))
        self.assertEqual(kode(findings), {"EKSPOSUR_POLA_GENERIK_TERDETEKSI"})


class TestModulPort(unittest.TestCase):
    def test_port_terbuka_terdeteksi(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 6379))
        s.listen(1)
        try:
            findings, info = pindai_port("127.0.0.1", timeout=1.0)
        finally:
            s.close()
        self.assertIn("PORT_TERBUKA_6379", kode(findings))
        self.assertEqual(next(f for f in findings if f.kode == "PORT_TERBUKA_6379").level, Level.HIGH)
        self.assertIn({"port": 6379, "layanan": "Redis"}, info["port_terbuka"])

        def test_port_tertutup_tidak_dilaporkan(self):
        findings, info = pindai_port("127.0.0.1", timeout=0.3)
        self.assertEqual(findings, [])
        self.assertEqual(info["port_terbuka"], [])
        
    def test_port_audit_tidak_disertakan_dalam_pemindaian(self):
        from auditkeamananweb.modul_port import DAFTAR_PORT_BAWAAN
        portnya = {p for p, *_ in DAFTAR_PORT_BAWAAN}
        self.assertFalse(portnya & {80, 443, 8080, 8443})


# ------------------------------------------------------------------ integrasi (server lokal)

class _Handler(BaseHTTPRequestHandler):
    def version_string(self):
        return "TestServer/1.2.3"

    def do_GET(self):
        if self.path.startswith("/r"):
            self.send_response(302)
            self.send_header("Location", "http://evil.invalid/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/.env":
            # satu path sensitif sungguh berbeda dari halaman generik, supaya tes Modul 5
            # tetap menguji temuan yang asli dan bukan tersaring sebagai pola generik.
            body = b"DB_PASSWORD=rahasia"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        isi = getattr(self.server, "isi", b"<html>halo</html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=abc123; Path=/")
        self.send_header("Content-Length", str(len(isi)))
        self.end_headers()
        self.wfile.write(isi)

    def log_message(self, *args):
        pass


class _Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass  # klien audit sengaja memutus koneksi (mis. setelah verifikasi sertifikat gagal)


def _mulai_server(konteks_tls=None, handler_cls=_Handler):
    srv = _Server(("127.0.0.1", 0), handler_cls)
    srv.daemon_threads = True
    if konteks_tls is not None:
        srv.socket = konteks_tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _hentikan(srv):
    srv.shutdown()
    srv.server_close()


class TestIntegrasiHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.port = _mulai_server()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        _hentikan(cls.srv)

    def test_audit_http_biasa(self):
        (h,) = audit_keamanan_web([self.base + "/"], konfig=KonfigAudit(timeout=3))
        self.assertEqual(h.status, "DIPERIKSA")
        k = kode(h.findings)
        for harus in ("TLS_TANPA_ENKRIPSI", "HDR_CSP_HILANG", "COOKIE_TANPA_HTTPONLY", "BANNER_TERBUKA"):
            self.assertIn(harus, k)
        self.assertNotIn("HDR_HSTS_HILANG", k)
        self.assertEqual(h.skor, hitung_skor(h.findings))
        self.assertEqual(h.grade, tentukan_grade(h.skor))
        self.assertEqual(h.info["http"]["status"], 200)

    def test_redirect_ke_host_tak_berizin_tidak_diikuti(self):
        (h,) = audit_keamanan_web([self.base + "/r"], konfig=KonfigAudit(timeout=3))
        self.assertEqual(h.status, "DIPERIKSA")
        self.assertEqual(h.info["http"]["status"], 302)
        self.assertTrue(any("tidak diotorisasi" in c for c in h.catatan))

    def test_tidak_berizin_dilewati_tanpa_request(self):
        (h,) = audit_keamanan_web(["https://tidak-diizinkan.invalid"])
        self.assertEqual(h.status, "SKIPPED (Unauthorized)")
        self.assertIsNone(h.skor)
        self.assertEqual(h.findings, [])

    def test_target_tidak_valid(self):
        (h,) = audit_keamanan_web(["ftp://x.com"])
        self.assertEqual(h.status, "INVALID")

    def test_port_tertutup_error_jaringan_dan_lanjut(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port_mati = s.getsockname()[1]
        s.close()
        hasil = audit_keamanan_web(
            [f"http://127.0.0.1:{port_mati}/", self.base + "/"], konfig=KonfigAudit(timeout=2)
        )
        self.assertEqual([h.status for h in hasil], ["ERROR (Network)", "DIPERIKSA"])

    def test_alur_baseline_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            jalur = os.path.join(d, "baseline.json")
            url = self.base + "/"

            def jalankan(**kw):
                konfig = KonfigAudit(timeout=3, baseline=Baseline(jalur), **kw)
                return audit_keamanan_web([url], konfig=konfig)[0]

            self.srv.isi = b"<html>asli</html>"
            self.assertIn("INT_BASELINE_BARU", kode(jalankan(simpan_baseline=True).findings))
            self.assertNotIn("INT_KONTEN_BERUBAH", kode(jalankan().findings))
            self.srv.isi = b"<html>DEFACED</html>"
            try:
                self.assertIn("INT_KONTEN_BERUBAH", kode(jalankan().findings))
            finally:
                del self.srv.isi

    def test_modul_eksposur_dan_port_aktif_lewat_konfig(self):
        konfig = KonfigAudit(timeout=3, timeout_port=0.3, cek_eksposur=True, pindai_port=True)
        (h,) = audit_keamanan_web([self.base + "/"], konfig=konfig)
        self.assertIn("eksposur", h.info)
        self.assertEqual(h.info["eksposur"]["path_diperiksa"], len(DAFTAR_PATH_BAWAAN))
        self.assertIn("port", h.info)  # modul jalan walau kemungkinan tidak ada port terbuka

    def test_modul_opsional_mati_secara_bawaan(self):
        (h,) = audit_keamanan_web([self.base + "/"], konfig=KonfigAudit(timeout=3))
        self.assertNotIn("eksposur", h.info)
        self.assertNotIn("port", h.info)

    def test_laporan_teks_dan_json(self):
        laporan = audit_keamanan_web([self.base + "/", "https://tidak-diizinkan.invalid"])
        teks = format_teks(laporan)
        self.assertIn("RINGKASAN", teks)
        self.assertIn("SKIPPED (Unauthorized)", teks)
        data = json.loads(ke_json(laporan))
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["status"], "DIPERIKSA")
        self.assertTrue(all("level" in f for f in data[0]["findings"]))


@unittest.skipUnless(shutil.which("openssl"), "openssl tidak tersedia")
class TestIntegrasiTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        kunci, sert = os.path.join(cls.tmp, "k.pem"), os.path.join(cls.tmp, "c.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", kunci, "-out", sert,
             "-days", "30", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True,
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(sert, kunci)
        cls.srv, cls.port = _mulai_server(ctx)

    @classmethod
    def tearDownClass(cls):
        _hentikan(cls.srv)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_sertifikat_self_signed_terdeteksi(self):
        (h,) = audit_keamanan_web([f"https://127.0.0.1:{self.port}/"], konfig=KonfigAudit(timeout=5))
        self.assertEqual(h.status, "DIPERIKSA")
        k = kode(h.findings)
        self.assertTrue(k & {"TLS_CERT_SELF_SIGNED", "TLS_CERT_UNTRUSTED"}, k)
        self.assertNotIn("TLS_HANDSHAKE_GAGAL", k)
        self.assertIn(h.info["tls"]["protokol"], ("TLSv1.2", "TLSv1.3"))
        self.assertIn("http", h.info)  # Modul 2 tetap berjalan
        self.assertIn("HDR_HSTS_HILANG", k)  # HTTPS, jadi HSTS dituntut

    def test_server_non_tls_di_port_https(self):
        srv, port = _mulai_server()  # server HTTP biasa, diakses sebagai https
        try:
            (h,) = audit_keamanan_web([f"https://127.0.0.1:{port}/"], konfig=KonfigAudit(timeout=3))
        finally:
            _hentikan(srv)
        self.assertIn("TLS_HANDSHAKE_GAGAL", kode(h.findings))
        self.assertNotIn("http", h.info)
        self.assertEqual(h.status, "DIPERIKSA")


class TestCLIKonsenAktif(unittest.TestCase):
    """--cek-eksposur/--pindai-port tanpa --saya-punya-izin harus ditolak CLI (exit code != 0),
    sebagai pengaman tambahan di luar otorisasi domain."""

    @classmethod
    def setUpClass(cls):
        cls.srv, cls.port = _mulai_server()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        _hentikan(cls.srv)

    def _jalankan_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "auditkeamananweb", *args],
            capture_output=True, text=True, timeout=30,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )

    def test_ditolak_tanpa_penegasan_izin(self):
        for flag in ("--cek-eksposur", "--pindai-port"):
            with self.subTest(flag=flag):
                r = self._jalankan_cli(self.base + "/", flag)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("--saya-punya-izin", r.stderr)

    def test_berjalan_dengan_penegasan_izin(self):
        r = self._jalankan_cli(
            self.base + "/", "--cek-eksposur", "--pindai-port", "--saya-punya-izin",
            "--timeout-port", "0.3",
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("EKSPOSUR_PATH_TERBUKA", r.stdout)

    def test_tidak_perlu_penegasan_izin_tanpa_modul_aktif(self):
        r = self._jalankan_cli(self.base + "/")
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()

"""Aplikasi desktop (GUI) untuk AuditKeamananWeb.

Dibangun dengan tkinter (bawaan Python, tanpa dependensi tambahan untuk DIJALANKAN).
Untuk dipaketkan menjadi satu berkas .exe yang bisa diklik tanpa Python terpasang,
lihat build_exe.bat / README.md (butuh PyInstaller, hanya saat proses build).

Jalankan langsung dengan:  python gui_desktop.py
"""
from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from auditkeamananweb import KonfigAudit, Otorisasi, audit_keamanan_web
from auditkeamananweb.laporan import format_teks, ke_json
from auditkeamananweb.modul_integritas import Baseline
from auditkeamananweb.models import STATUS_OK, HasilTarget
from auditkeamananweb.otorisasi import DOMAIN_UJI_BAWAAN

JUDUL = "AuditKeamananWeb — Audit Keamanan Web"


class AplikasiAudit(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(JUDUL)
        self.geometry("980x760")
        self.minsize(820, 600)

        self._antrian: queue.Queue = queue.Queue()
        self._sedang_berjalan = False
        self._laporan: list[HasilTarget] = []

        self._bangun_ui()
        self.after(100, self._poll_antrian)

    # ------------------------------------------------------------------ UI

    def _bangun_ui(self) -> None:
        peringatan = tk.Label(
            self,
            text="⚠ Gunakan HANYA pada sistem yang Anda miliki atau yang Anda punya izin tertulis "
                 "untuk diuji. Target di luar daftar izin otomatis dilewati.",
            fg="#8a2a00", wraplength=940, justify="left", font=("Segoe UI", 9, "bold"),
        )
        peringatan.pack(fill="x", padx=10, pady=(8, 2))

        panel_atas = ttk.Panedwindow(self, orient="horizontal")
        panel_atas.pack(fill="both", expand=True, padx=10, pady=5)

        kiri = ttk.Frame(panel_atas)
        kanan = ttk.Frame(panel_atas)
        panel_atas.add(kiri, weight=1)
        panel_atas.add(kanan, weight=2)

        self._bangun_panel_input(kiri)
        self._bangun_panel_output(kanan)

        bawah = ttk.Frame(self)
        bawah.pack(fill="x", padx=10, pady=(0, 8))
        self.label_status = ttk.Label(bawah, text="Siap.")
        self.label_status.pack(side="left")
        self.progress = ttk.Progressbar(bawah, mode="determinate", length=260)
        self.progress.pack(side="right")

    def _bangun_panel_input(self, induk: ttk.Frame) -> None:
        ttk.Label(induk, text="Daftar target (satu URL/domain per baris):").pack(anchor="w")
        self.teks_target = scrolledtext.ScrolledText(induk, height=8, width=42)
        self.teks_target.pack(fill="both", expand=True, pady=(0, 6))
        ttk.Button(induk, text="Muat dari berkas…", command=self._muat_target).pack(anchor="w")

        ttk.Label(induk, text="Daftar domain yang diizinkan (opsional,\nsatu per baris; '*.domain' untuk subdomain):").pack(
            anchor="w", pady=(10, 0)
        )
        self.teks_izin = scrolledtext.ScrolledText(induk, height=5, width=42)
        self.teks_izin.pack(fill="both", expand=False, pady=(0, 2))
        ttk.Label(
            induk,
            text="Domain uji bawaan sudah otomatis diizinkan: " + ", ".join(DOMAIN_UJI_BAWAAN),
            foreground="#555555", wraplength=380, justify="left", font=("Segoe UI", 8),
        ).pack(anchor="w", pady=(0, 6))
        ttk.Button(induk, text="Muat dari berkas…", command=self._muat_izin).pack(anchor="w")

        kotak = ttk.LabelFrame(induk, text="Pengaturan")
        kotak.pack(fill="x", pady=10)

        baris1 = ttk.Frame(kotak)
        baris1.pack(fill="x", pady=2)
        ttk.Label(baris1, text="Timeout (detik):").pack(side="left")
        self.var_timeout = tk.StringVar(value="8")
        ttk.Entry(baris1, textvariable=self.var_timeout, width=6).pack(side="left", padx=4)
        ttk.Label(baris1, text="Maks redirect:").pack(side="left", padx=(10, 0))
        self.var_redirect = tk.StringVar(value="5")
        ttk.Entry(baris1, textvariable=self.var_redirect, width=6).pack(side="left", padx=4)

        self.var_cve = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            kotak, text="Modul 7: cocokkan versi dari header vs CVE publik (pasif, aman)",
            variable=self.var_cve,
        ).pack(anchor="w")

        self.var_eksposur = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            kotak, text="Modul 5: cek path/file sensitif terekspos (.env, .git, backup, …)",
            variable=self.var_eksposur, command=self._ubah_opsi_aktif,
        ).pack(anchor="w")

        self.var_port = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            kotak, text="Modul 6: pindai port umum terbuka (FTP, SMB, database, RDP, …)",
            variable=self.var_port, command=self._ubah_opsi_aktif,
        ).pack(anchor="w")

        baris_port = ttk.Frame(kotak)
        baris_port.pack(fill="x", pady=2)
        ttk.Label(baris_port, text="Timeout per port (detik):").pack(side="left")
        self.var_timeout_port = tk.StringVar(value="1.5")
        ttk.Entry(baris_port, textvariable=self.var_timeout_port, width=6).pack(side="left", padx=4)

        self.var_izin_tegas = tk.BooleanVar(value=False)
        self.cek_izin_tegas = ttk.Checkbutton(
            kotak,
            text="Saya punya izin tertulis dari pemilik target untuk Modul 5/6 di atas",
            variable=self.var_izin_tegas, state="disabled",
        )
        self.cek_izin_tegas.pack(anchor="w", pady=(4, 0))

        kotak_bl = ttk.LabelFrame(induk, text="Modul 3: integritas konten (opsional)")
        kotak_bl.pack(fill="x", pady=6)
        baris_bl = ttk.Frame(kotak_bl)
        baris_bl.pack(fill="x", pady=2)
        self.var_baseline = tk.StringVar(value="")
        ttk.Entry(baris_bl, textvariable=self.var_baseline, width=24).pack(side="left", fill="x", expand=True)
        ttk.Button(baris_bl, text="…", width=3, command=self._pilih_baseline).pack(side="left", padx=2)
        self.var_simpan_bl = tk.BooleanVar(value=False)
        ttk.Checkbutton(kotak_bl, text="Simpan hash bila belum ada baseline", variable=self.var_simpan_bl).pack(anchor="w")
        self.var_perbarui_bl = tk.BooleanVar(value=False)
        ttk.Checkbutton(kotak_bl, text="Perbarui baseline bila konten berubah", variable=self.var_perbarui_bl).pack(anchor="w")

        self.tombol_jalankan = ttk.Button(induk, text="▶  Jalankan Audit", command=self._mulai_audit)
        self.tombol_jalankan.pack(fill="x", pady=(10, 0), ipady=6)

    def _bangun_panel_output(self, induk: ttk.Frame) -> None:
        ttk.Label(induk, text="Hasil:").pack(anchor="w")
        self.teks_output = scrolledtext.ScrolledText(induk, font=("Consolas", 9))
        self.teks_output.pack(fill="both", expand=True, pady=(0, 6))
        self.teks_output.configure(state="disabled")

        baris = ttk.Frame(induk)
        baris.pack(fill="x")
        self.tombol_simpan_txt = ttk.Button(baris, text="Simpan sebagai .txt", command=self._simpan_txt, state="disabled")
        self.tombol_simpan_txt.pack(side="left", padx=(0, 4))
        self.tombol_simpan_json = ttk.Button(baris, text="Simpan sebagai .json", command=self._simpan_json, state="disabled")
        self.tombol_simpan_json.pack(side="left")
        ttk.Button(baris, text="Tentang", command=self._tentang).pack(side="right")

    # ------------------------------------------------------------------ aksi kecil

    def _ubah_opsi_aktif(self) -> None:
        aktif = self.var_eksposur.get() or self.var_port.get()
        self.cek_izin_tegas.configure(state="normal" if aktif else "disabled")
        if not aktif:
            self.var_izin_tegas.set(False)

    def _muat_target(self) -> None:
        jalur = filedialog.askopenfilename(title="Pilih berkas daftar target", filetypes=[("Teks", "*.txt"), ("Semua", "*.*")])
        if jalur:
            with open(jalur, encoding="utf-8-sig") as f:
                self.teks_target.insert("end", f.read())

    def _muat_izin(self) -> None:
        jalur = filedialog.askopenfilename(title="Pilih berkas daftar izin", filetypes=[("Teks", "*.txt"), ("Semua", "*.*")])
        if jalur:
            with open(jalur, encoding="utf-8-sig") as f:
                self.teks_izin.insert("end", f.read())

    def _pilih_baseline(self) -> None:
        jalur = filedialog.asksaveasfilename(
            title="Berkas baseline (dibuat bila belum ada)", defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Semua", "*.*")],
        )
        if jalur:
            self.var_baseline.set(jalur)

    def _tentang(self) -> None:
        messagebox.showinfo(
            "Tentang",
            f"{JUDUL}\n\n"
            "Audit keamanan web pasif: TLS & sertifikat, header HTTP & cookie, "
            "integritas konten, serta modul opt-in untuk eksposur path, pindai port, "
            "dan pencocokan versi vs CVE publik.\n\n"
            "Gunakan hanya pada sistem yang Anda miliki atau yang Anda punya izin tertulis "
            "untuk diuji.",
        )

    def _baris(self, teks: str) -> list[str]:
        return [b.strip() for b in teks.splitlines() if b.strip() and not b.strip().startswith("#")]

    # ------------------------------------------------------------------ jalankan audit

    def _mulai_audit(self) -> None:
        if self._sedang_berjalan:
            return
        daftar = self._baris(self.teks_target.get("1.0", "end"))
        if not daftar:
            messagebox.showwarning(JUDUL, "Isi dulu daftar target (minimal satu baris).")
            return
        if (self.var_eksposur.get() or self.var_port.get()) and not self.var_izin_tegas.get():
            messagebox.showwarning(
                JUDUL,
                "Modul 5 (eksposur) dan/atau Modul 6 (pindai port) aktif. Centang dulu kotak "
                "penegasan izin sebelum menjalankan audit.",
            )
            return
        try:
            timeout = float(self.var_timeout.get())
            redirect = int(self.var_redirect.get())
            timeout_port = float(self.var_timeout_port.get())
        except ValueError:
            messagebox.showerror(JUDUL, "Timeout/redirect harus berupa angka.")
            return

        izin_entri = self._baris(self.teks_izin.get("1.0", "end"))
        try:
            otorisasi = Otorisasi(izin_entri)
        except ValueError as e:
            messagebox.showerror(JUDUL, f"Daftar izin tidak valid: {e}")
            return

        baseline = None
        jalur_bl = self.var_baseline.get().strip()
        if jalur_bl:
            try:
                baseline = Baseline(jalur_bl)
            except ValueError as e:
                messagebox.showerror(JUDUL, f"Berkas baseline tidak valid: {e}")
                return

        konfig = KonfigAudit(
            timeout=timeout, maks_redirect=redirect, baseline=baseline,
            simpan_baseline=self.var_simpan_bl.get(), perbarui_baseline=self.var_perbarui_bl.get(),
            cek_eksposur=self.var_eksposur.get(), pindai_port=self.var_port.get(),
            cek_cve=self.var_cve.get(), timeout_port=timeout_port,
        )

        self._laporan = []
        self._atur_output("")
        self.tombol_simpan_txt.configure(state="disabled")
        self.tombol_simpan_json.configure(state="disabled")
        self.tombol_jalankan.configure(state="disabled", text="⏳  Sedang berjalan…")
        self._sedang_berjalan = True
        self.progress.configure(maximum=len(daftar), value=0)

        threading.Thread(
            target=self._kerja_latar, args=(daftar, otorisasi, konfig), daemon=True,
        ).start()

    def _kerja_latar(self, daftar: list[str], otorisasi: Otorisasi, konfig: KonfigAudit) -> None:
        for i, target in enumerate(daftar, start=1):
            (hasil,) = audit_keamanan_web([target], otorisasi, konfig)
            self._antrian.put(("progres", i, len(daftar), hasil))
        self._antrian.put(("selesai", None, None, None))

    def _poll_antrian(self) -> None:
        try:
            while True:
                jenis, i, total, hasil = self._antrian.get_nowait()
                if jenis == "progres":
                    self._laporan.append(hasil)
                    self.progress.configure(value=i)
                    self.label_status.configure(text=f"Memeriksa target {i}/{total}: {hasil.target}")
                    self._tambah_output(_blok_satu_target(hasil))
                elif jenis == "selesai":
                    self._selesai_audit()
        except queue.Empty:
            pass
        self.after(100, self._poll_antrian)

    def _selesai_audit(self) -> None:
        self._sedang_berjalan = False
        self.tombol_jalankan.configure(state="normal", text="▶  Jalankan Audit")
        self.tombol_simpan_txt.configure(state="normal")
        self.tombol_simpan_json.configure(state="normal")
        diperiksa = sum(1 for h in self._laporan if h.status == STATUS_OK)
        self.label_status.configure(text=f"Selesai. {diperiksa}/{len(self._laporan)} target diperiksa penuh.")
        self._tambah_output("\n" + "=" * 72 + "\nSELESAI.\n")

    # ------------------------------------------------------------------ output & simpan

    def _atur_output(self, teks: str) -> None:
        self.teks_output.configure(state="normal")
        self.teks_output.delete("1.0", "end")
        self.teks_output.insert("end", teks)
        self.teks_output.configure(state="disabled")

    def _tambah_output(self, teks: str) -> None:
        self.teks_output.configure(state="normal")
        self.teks_output.insert("end", teks)
        self.teks_output.see("end")
        self.teks_output.configure(state="disabled")

    def _simpan_txt(self) -> None:
        jalur = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Teks", "*.txt")])
        if jalur:
            with open(jalur, "w", encoding="utf-8") as f:
                f.write(format_teks(self._laporan))
            messagebox.showinfo(JUDUL, f"Laporan disimpan ke:\n{jalur}")

    def _simpan_json(self) -> None:
        jalur = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if jalur:
            with open(jalur, "w", encoding="utf-8") as f:
                f.write(ke_json(self._laporan))
            messagebox.showinfo(JUDUL, f"Laporan JSON disimpan ke:\n{jalur}")


def _blok_satu_target(h: HasilTarget) -> str:
    isi = format_teks([h])
    # buang bagian RINGKASAN (hanya relevan untuk keseluruhan laporan, diulang tiap panggilan format_teks)
    return isi.split("\nRINGKASAN")[0] + "\n"


def main() -> None:
    app = AplikasiAudit()
    app.mainloop()


if __name__ == "__main__":
    main()

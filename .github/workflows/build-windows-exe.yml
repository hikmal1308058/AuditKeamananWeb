@echo off
REM Paketkan AuditKeamananWeb (GUI) menjadi satu berkas AuditKeamananWeb.exe.
REM Jalankan skrip ini DI WINDOWS, di dalam folder project ini (tempat gui_desktop.py berada).
REM Build HARUS dilakukan di Windows -- PyInstaller membuat .exe untuk sistem operasi
REM tempat ia dijalankan, jadi build dari Linux/Mac tidak akan menghasilkan .exe Windows.

where python >nul 2>nul
if errorlevel 1 (
    echo [GAGAL] Python tidak ditemukan di PATH. Pasang Python 3.9+ dari python.org
    echo         dan centang "Add python.exe to PATH" saat instalasi, lalu coba lagi.
    pause
    exit /b 1
)

echo [1/3] Memasang PyInstaller...
python -m pip install --upgrade pyinstaller
if errorlevel 1 goto gagal

echo [2/3] Membersihkan hasil build sebelumnya...
rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
del /q AuditKeamananWeb.spec 2>nul

echo [3/3] Membangun AuditKeamananWeb.exe ...
python -m PyInstaller --onefile --windowed --name AuditKeamananWeb gui_desktop.py
if errorlevel 1 goto gagal

echo.
echo [SELESAI] Berkas .exe ada di: dist\AuditKeamananWeb.exe
echo Anda bisa menyalin berkas itu ke mana saja -- tidak perlu Python terpasang untuk menjalankannya.
pause
exit /b 0

:gagal
echo.
echo [GAGAL] Proses build berhenti. Lihat pesan error di atas.
pause
exit /b 1

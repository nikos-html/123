@echo off
echo ============================================
echo   SecureDoc Admin Panel - Instalator
echo ============================================
echo.

REM Sprawdź czy Python jest zainstalowany
python --version >nul 2>&1
if errorlevel 1 (
    echo [BLAD] Python nie jest zainstalowany!
    echo Pobierz go z: https://www.python.org/downloads/
    echo.
    echo WAZNE: Zaznacz "Add Python to PATH" podczas instalacji!
    echo.
    pause
    exit /b 1
)

echo [1/4] Instaluje wymagane biblioteki...
pip install psycopg[binary] bcrypt customtkinter pyinstaller --quiet

echo [2/4] Tworze plik .exe (to moze potrwac 1-2 minuty)...
pyinstaller --onefile --windowed --name "SecureDoc_Admin" --icon=NONE SecureDoc_Admin_GUI.py

echo [3/4] Czyszcze pliki tymczasowe...
rmdir /s /q build 2>nul
del /q SecureDoc_Admin.spec 2>nul

echo [4/4] Gotowe!
echo.
echo ============================================
echo   Aplikacja znajduje sie w: dist\SecureDoc_Admin.exe
echo ============================================
echo.
echo Mozesz ja przeniesc gdziekolwiek i uzywac!
echo.
pause

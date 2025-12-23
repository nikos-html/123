@echo off
echo ============================================
echo   SecureDoc Admin Tool - Instalator
echo ============================================
echo.

REM Sprawdź czy Python jest zainstalowany
python --version >nul 2>&1
if errorlevel 1 (
    echo [BLAD] Python nie jest zainstalowany!
    echo Pobierz go z: https://www.python.org/downloads/
    echo Zaznacz "Add Python to PATH" podczas instalacji!
    pause
    exit /b 1
)

echo [1/3] Instaluje wymagane biblioteki...
pip install psycopg[binary] bcrypt pyinstaller --quiet

echo [2/3] Tworze plik .exe...
pyinstaller --onefile --console --name "SecureDoc_Admin" --icon=NONE admin_tool.py

echo [3/3] Gotowe!
echo.
echo ============================================
echo   Plik .exe znajduje sie w folderze: dist\
echo   Uruchom: dist\SecureDoc_Admin.exe
echo ============================================
pause

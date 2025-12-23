# SecureDoc Admin Tool

Lokalne narzędzie do zarządzania bazą danych SecureDoc.

## Szybka instalacja (Windows)

1. Pobierz te pliki na komputer:
   - `admin_tool.py`
   - `build_exe.bat`

2. Kliknij dwukrotnie na `build_exe.bat`

3. Poczekaj aż się zbuduje (~1-2 minuty)

4. Gotowy plik `.exe` znajdziesz w folderze `dist\SecureDoc_Admin.exe`

## Wymagania

- Windows 10/11
- Python 3.8+ (https://www.python.org/downloads/)
  - ⚠️ Podczas instalacji zaznacz **"Add Python to PATH"**

## Użycie

1. Uruchom `SecureDoc_Admin.exe`
2. Przy pierwszym uruchomieniu wklej `DATABASE_URL` z Railway:
   - Railway → Twój projekt → Postgres → Variables → DATABASE_URL
3. Wybierz opcję z menu

## Funkcje

- 📊 Statystyki bazy danych
- 👥 Zarządzanie użytkownikami (dodaj admina, usuń)
- 📄 Zarządzanie dokumentami (lista, szukaj, usuń)
- 🔑 Zarządzanie kodami (generuj, usuń wykorzystane)
- ⚠️ PANIC - wyczyść całą bazę

## Bezpieczeństwo

- DATABASE_URL jest przechowywany tylko w pamięci
- Musisz go podać przy każdym uruchomieniu (dla bezpieczeństwa)
- Możesz też ustawić zmienną środowiskową DATABASE_URL

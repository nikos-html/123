# 🔐 Security Hardening - Zmiany zabezpieczeń

## Wprowadzone zmiany

### 1. ACCESS CODES (KRYTYCZNE) ✅
- **Usunięto**: Wszystkie hardcoded access_code
- **Dodano**: Kody generowane przez backend z `secrets` module
- **Dodano**: Kolumna `expires_at` w tabeli `one_time_codes` (TTL 72h)
- **Dodano**: Sprawdzanie `used=FALSE` i `expires_at > NOW()` przy walidacji
- **Dodano**: Oznaczanie kodu jako `used=TRUE` po użyciu
- **Plik**: `app.py` - endpoint `/api/auth/validate-code`

### 2. OCHRONA PRZED ZGADYWANIEM ✅
- **Dodano**: Rate limit 3 req / 15 min na `/api/auth/validate-code`
- **Dodano**: Rate limit 3 req / 15 min na `/api/auth/admin-login`
- **Dodano**: Rate limit 5 req / 15 min na `/api/auth/login` i `/api/auth/create-user`
- **Dodano**: Zwraca 429 po przekroczeniu limitu
- **Plik**: `app.py` - dekoratory `@limiter.limit()`

### 3. ADMIN ACCESS (KRYTYCZNE) ✅
- **Usunięto**: Hardcoded admin credentials (`mamba/MangoMango67`, `admin/admin123`)
- **Usunięto**: Endpoint `/api/seed` (tworzący admina z plaintext)
- **Dodano**: Hasła hashowane bcrypt
- **Dodano**: Dedykowany endpoint `/api/auth/admin-login`
- **Dodano**: JWT tokeny dla sesji admina (24h expiration)
- **Dodano**: Decorator `@require_admin` sprawdzający JWT
- **Pliki**: `app.py`, `admin-login.html`, `admin.html`

### 4. ADMIN IP ALLOWLIST ✅
- **Dodano**: Opcjonalny allowlist IP w `ADMIN_IP_ALLOWLIST` env var
- **Dodano**: Obsługa Cloudflare `CF-Connecting-IP` header
- **Plik**: `app.py` - funkcja `require_admin()`

### 5. FEATURE FLAGS (KILL SWITCH) ✅
- **Dodano**: `DISABLE_SIGNUP` - blokuje rejestrację (403)
- **Dodano**: `DISABLE_ADMIN` - blokuje panel admina (403)
- **Plik**: `app.py`

### 6. CAPTCHA (Cloudflare Turnstile) ✅
- **Dodano**: Widget Turnstile na:
  - `/admin-login.html` (wymagany)
  - `/login.html` (wymagany)
  - `/gen.html` - walidacja kodów (wymagany)
- **Dodano**: Weryfikacja tokenu w backendzie
- **Plik**: `app.py` - funkcja `verify_turnstile_sync()`
- **Site key**: `0x4AAAAAACIETFZW2JNexJYL`
- **Secret key**: W zmiennej `TURNSTILE_SECRET_KEY`

### 7. RATE LIMIT GLOBALNY ✅
- **Dodano**: Default limit 100 req/hour per client
- **Dodano**: Identyfikator klienta = hash(IP + User-Agent)
- **Plik**: `app.py` - Flask-Limiter

### 8. WALIDACJA + SANITIZE ✅
- **Dodano**: Funkcja `sanitize_input()` używająca `bleach`
- **Dodano**: Usuwanie HTML/JS z inputów
- **Dodano**: Limity długości inputów
- **Plik**: `app.py`

### 9. BODY SIZE LIMIT ✅
- **Dodano**: Max 10KB na request body
- **Plik**: `app.py` - `@app.before_request`

### 10. LOGI / DETEKCJA ATAKU ✅
- **Dodano**: Logowanie 403, 429
- **Dodano**: Logowanie prób admin access
- **Dodano**: Logowanie invalid tokens
- **NIE loguje**: Payloadów użytkownika
- **Plik**: `app.py` - logger 'security'

```
# SECURITY: Gdzie zrobić scale=0 przy ataku:
# W Railway dashboard -> Settings -> Scale to 0
# Lub: railway down
```

### 11. BEZPIECZEŃSTWO GLOBALNE ✅
- **Dodano**: Security headers (helmet-like):
  - `X-Content-Type-Options: nosniff`
  - `X-XSS-Protection: 1; mode=block`
  - `X-Frame-Options: SAMEORIGIN`
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `Referrer-Policy`
- **Dodano**: CORS tylko dla dozwolonych origins
- **Dodano**: `Cache-Control: no-store` dla API
- **Usunięto**: Debug mode na produkcji
- **Plik**: `app.py` - `@app.after_request`

### 12. ZAKAZ BACKDOORÓW ✅
- **Usunięto**: Wszystkie hardcoded credentials
- **Usunięto**: Endpoint `/clear-codes` (teraz tylko admin API)
- **Usunięto**: Magiczne hasła typu `if code == "XYZ"`
- **Audit**: Brak uniwersalnych kodów w kodzie

---

## Pliki zmienione

| Plik | Zmiana |
|------|--------|
| `app.py` | Kompletnie przepisany z zabezpieczeniami |
| `admin-login.html` | Turnstile + JWT auth |
| `admin.html` | JWT auth dla wszystkich requestów |
| `login.html` | Turnstile + JWT storage |
| `gen.html` | Turnstile dla walidacji kodów |
| `requirements.txt` | Nowe zależności security |
| `create_admin.py` | Skrypt do tworzenia admina z bcrypt |
| `.env.example` | Template zmiennych środowiskowych |

---

## Nowe zależności

```
flask-limiter==3.5.0   # Rate limiting
bcrypt==4.1.3          # Password hashing
PyJWT==2.10.1          # JWT tokens
bleach==6.3.0          # HTML sanitization
httpx==0.28.1          # Async HTTP client
requests==2.32.3       # Sync HTTP client
```

---

## Konfiguracja na Railway

### Wymagane zmienne środowiskowe:
```
DATABASE_URL=<already set>
JWT_SECRET=<wygeneruj: python -c "import secrets; print(secrets.token_hex(32))">
TURNSTILE_SECRET_KEY=0x4AAAAAACIETFZW2JPN4TewZskRq48ujK4
```

### Opcjonalne:
```
DISABLE_SIGNUP=false
DISABLE_ADMIN=false
ADMIN_IP_ALLOWLIST=1.2.3.4,5.6.7.8
ACCESS_CODE_TTL_HOURS=72
WEBHOOK_SECRET=<twoj-secret>
```

---

## Tworzenie admina

Po deployu, uruchom w Railway shell:
```bash
python create_admin.py admin TwojeNoweHaslo123!
```

Lub migracja istniejących haseł:
```bash
python create_admin.py --migrate
```

---

## Cloudflare Turnstile

Site key jest już w HTML: `0x4AAAAAACIETFZW2JNexJYL`

Jeśli chcesz zmienić:
1. Idź do Cloudflare Dashboard -> Turnstile
2. Utwórz nowy site
3. Zaktualizuj `data-sitekey` w HTML
4. Zaktualizuj `TURNSTILE_SECRET_KEY` w Railway

---

## Testowanie zabezpieczeń

### Rate limiting:
```bash
for i in {1..10}; do curl -X POST https://mambagenerator.up.railway.app/api/auth/validate-code -H "Content-Type: application/json" -d '{"code":"TEST"}'; done
# Po 3 requestach: {"error": "Too many requests..."}
```

### JWT wymagany:
```bash
curl https://mambagenerator.up.railway.app/api/admin/users
# {"error": "Admin authentication required"}
```

### Turnstile wymagany:
```bash
curl -X POST https://mambagenerator.up.railway.app/api/auth/admin-login -H "Content-Type: application/json" -d '{"username":"admin","password":"test"}'
# {"error": "CAPTCHA verification required"}
```

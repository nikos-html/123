# Bezpieczeństwo - Przeniesienie logiki na backend

## Co zostało zmienione

### 1. Backend (app.py)

**Nowy endpoint `/api/documents/{id}/check`:**
```python
GET /api/documents/{id}/check?token=xxx
```
- Zwraca TYLKO `{ "exists": true }` lub `{ "exists": false }`
- Wymaga tokena - bez tokena zwraca 403
- Żadne dane dokumentu NIE są eksponowane

**Istniejący endpoint `/api/documents/{id}`:**
```python
GET /api/documents/{id}?token=xxx
```
- Zwraca dane dokumentu TYLKO z prawidłowym tokenem
- HTTP 404 = dokument nie istnieje
- HTTP 403 = brak/nieprawidłowy token

### 2. Frontend (assets/card.js)

**Przed:**
```javascript
fetch(`/api/documents/${docId}`)  // BEZ TOKENA!
```

**Po:**
```javascript
let fetchUrl = `/api/documents/${docId}`;
if (viewToken) {
  fetchUrl += `?token=${viewToken}`;
}
fetch(fetchUrl)
```

- Token jest pobierany z URL (`?token=xxx`) lub `sessionStorage`
- Błędy są obsługiwane na podstawie kodów HTTP z backendu

---

## Dlaczego tego nie da się podejrzeć w DevTools?

### 1. **Logika walidacji jest na serwerze**
- Sprawdzenie czy dokument istnieje → backend
- Walidacja tokena → backend  
- Decyzja o dostępie → backend

### 2. **Frontend nie zawiera wrażliwych danych**
- Brak ID dokumentów w kodzie JS
- Brak tokenów zakodowanych w JS
- Brak warunków biznesowych (np. "jeśli użytkownik X to...")

### 3. **Co widzi atakujący w DevTools?**
```javascript
// Widzi tylko:
fetch('/api/documents/123?token=abc')
// Ale:
// - Nie zna prawidłowego ID (losowe)
// - Nie zna tokena (generowany na backendzie)
// - Próba bez tokena = 403 Forbidden
// - Próba z nieprawidłowym tokenem = 403 Forbidden
// - Próba z nieistniejącym ID = 404 Not Found
```

### 4. **Token jest unikalny dla każdego dokumentu**
```python
view_token = secrets.token_urlsafe(16)  # 128 bitów entropii
```
- Praktycznie niemożliwy do zgadnięcia
- Generowany na backendzie przy tworzeniu dokumentu

---

## Struktura plików

```
/app/
├── app.py                    # Backend Flask - CAŁA LOGIKA TUTAJ
│   ├── /api/documents/{id}/check  # Sprawdzanie istnienia (nowy)
│   ├── /api/documents/{id}        # Pobieranie danych (wymaga tokena)
│   └── /api/documents/create-and-get-id  # Tworzenie (zwraca ID + token)
│
├── assets/
│   ├── card.js               # Frontend - TYLKO fetch + wyświetlanie
│   └── id.js                 # Frontend - TYLKO fetch + wyświetlanie
│
├── id.html                   # Strona dokumentu
├── home.html                 # Strona główna
├── card.html                 # Karta dokumentu
└── gen.html                  # Generator
```

---

## Gotowość do wdrożenia Railway

✅ Backend używa zmiennych środowiskowych:
- `DATABASE_URL` - połączenie PostgreSQL
- `JWT_SECRET` - klucz JWT
- `TURNSTILE_SECRET_KEY` - Cloudflare CAPTCHA

✅ Procfile już istnieje:
```
web: gunicorn app:app
```

✅ requirements.txt zawiera wszystkie zależności

---

## Podsumowanie

| Aspekt | Przed | Po |
|--------|-------|-----|
| Logika walidacji | Frontend JS | Backend Python |
| Sprawdzanie istnienia | Frontend | `/api/documents/{id}/check` |
| Eksponowane ID/tokeny | W kodzie JS | Tylko w URL (dynamiczne) |
| Komunikaty błędów | Hardcoded w JS | Bazują na HTTP kodach |

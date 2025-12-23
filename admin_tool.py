#!/usr/bin/env python3
"""
SecureDoc Admin Tool - Lokalne narzędzie do zarządzania bazą danych
Uruchom: python admin_tool.py
"""

import os
import sys
import getpass
from datetime import datetime, timedelta

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    print("Instaluję wymagane biblioteki...")
    os.system("pip install psycopg[binary]")
    import psycopg
    from psycopg.rows import dict_row

# ============================================================================
# KONFIGURACJA - WPISZ SWÓJ DATABASE_URL Z RAILWAY
# ============================================================================
DATABASE_URL = os.environ.get('DATABASE_URL', '')

# Jeśli nie ma w zmiennych środowiskowych, zapytaj użytkownika
if not DATABASE_URL:
    print("\n" + "="*60)
    print("  SecureDoc Admin Tool")
    print("="*60)
    print("\nPodaj DATABASE_URL z Railway (znajdziesz w Variables):")
    print("Format: postgresql://user:password@host:port/database")
    DATABASE_URL = input("\nDATABASE_URL: ").strip()

def get_db():
    """Połącz z bazą danych"""
    return psycopg.connect(DATABASE_URL)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    clear_screen()
    print("\n" + "="*60)
    print("  🔒 SecureDoc Admin Tool")
    print("="*60)

def print_menu():
    print("""
  📊 STATYSTYKI
    [1] Pokaż statystyki bazy danych
    
  👥 UŻYTKOWNICY
    [2] Lista użytkowników
    [3] Dodaj admina
    [4] Usuń użytkownika
    
  📄 DOKUMENTY
    [5] Lista dokumentów
    [6] Szukaj dokumentu po ID
    [7] Usuń dokument
    [8] Usuń wszystkie dokumenty
    
  🔑 KODY DOSTĘPU
    [9] Lista kodów
    [10] Generuj nowe kody
    [11] Usuń wykorzystane kody
    [12] Usuń wszystkie kody
    
  ⚠️  NIEBEZPIECZNE
    [13] WYCZYŚĆ CAŁĄ BAZĘ (PANIC)
    
  [0] Wyjście
    """)

def show_stats():
    """Pokaż statystyki bazy danych"""
    print_header()
    print("\n📊 STATYSTYKI BAZY DANYCH\n")
    
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # Użytkownicy
        cur.execute("SELECT COUNT(*) FROM users")
        users_count = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM users WHERE is_admin = TRUE")
        admins_count = cur.fetchone()[0]
        
        # Dokumenty
        cur.execute("SELECT COUNT(*) FROM generated_documents")
        docs_count = cur.fetchone()[0]
        
        # Kody
        cur.execute("SELECT COUNT(*) FROM one_time_codes")
        codes_total = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM one_time_codes WHERE used = FALSE")
        codes_unused = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM one_time_codes WHERE used = TRUE")
        codes_used = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        print(f"  👥 Użytkownicy:      {users_count}")
        print(f"  👑 Administratorzy:  {admins_count}")
        print(f"  📄 Dokumenty:        {docs_count}")
        print(f"  🔑 Kody łącznie:     {codes_total}")
        print(f"     ├─ Niewykorzystane: {codes_unused}")
        print(f"     └─ Wykorzystane:    {codes_used}")
        
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def list_users():
    """Lista wszystkich użytkowników"""
    print_header()
    print("\n👥 LISTA UŻYTKOWNIKÓW\n")
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("SELECT id, username, is_admin, has_access, created_at FROM users ORDER BY id")
        users = cur.fetchall()
        cur.close()
        conn.close()
        
        if not users:
            print("  Brak użytkowników")
        else:
            print(f"  {'ID':<6} {'Username':<20} {'Admin':<8} {'Dostęp':<8} {'Data'}")
            print("  " + "-"*70)
            for u in users:
                admin = "✅" if u['is_admin'] else "❌"
                access = "✅" if u['has_access'] else "❌"
                date = u['created_at'].strftime("%Y-%m-%d") if u['created_at'] else "-"
                print(f"  {u['id']:<6} {u['username']:<20} {admin:<8} {access:<8} {date}")
                
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def add_admin():
    """Dodaj nowego admina"""
    print_header()
    print("\n👑 DODAJ ADMINISTRATORA\n")
    
    try:
        import bcrypt
    except ImportError:
        os.system("pip install bcrypt")
        import bcrypt
    
    username = input("  Username: ").strip()
    password = getpass.getpass("  Hasło: ")
    
    if not username or not password:
        print("  ❌ Username i hasło są wymagane")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    try:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (username, password, has_access, is_admin)
            VALUES (%s, %s, TRUE, TRUE)
            ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password, is_admin = TRUE
        """, (username, hashed))
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"\n  ✅ Administrator '{username}' został dodany/zaktualizowany")
        
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def delete_user():
    """Usuń użytkownika"""
    print_header()
    print("\n🗑️ USUŃ UŻYTKOWNIKA\n")
    
    user_id = input("  ID użytkownika do usunięcia: ").strip()
    
    if not user_id.isdigit():
        print("  ❌ Nieprawidłowe ID")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    confirm = input(f"  Czy na pewno usunąć użytkownika {user_id}? (tak/nie): ").strip().lower()
    
    if confirm != 'tak':
        print("  ❌ Anulowano")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = %s", (int(user_id),))
        deleted = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        
        if deleted:
            print(f"\n  ✅ Użytkownik {user_id} został usunięty")
        else:
            print(f"\n  ⚠️ Nie znaleziono użytkownika o ID {user_id}")
            
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def list_documents():
    """Lista dokumentów"""
    print_header()
    print("\n📄 LISTA DOKUMENTÓW (ostatnie 20)\n")
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT id, name, surname, pesel, view_token, created_at 
            FROM generated_documents 
            ORDER BY created_at DESC 
            LIMIT 20
        """)
        docs = cur.fetchall()
        cur.close()
        conn.close()
        
        if not docs:
            print("  Brak dokumentów")
        else:
            for d in docs:
                date = d['created_at'].strftime("%Y-%m-%d %H:%M") if d['created_at'] else "-"
                print(f"  ID: {d['id']}")
                print(f"  Imię: {d['name']} {d['surname']}")
                print(f"  PESEL: {d['pesel']}")
                print(f"  Token: {d['view_token']}")
                print(f"  Data: {date}")
                print("  " + "-"*50)
                
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def search_document():
    """Szukaj dokumentu po ID"""
    print_header()
    print("\n🔍 SZUKAJ DOKUMENTU\n")
    
    doc_id = input("  ID dokumentu: ").strip()
    
    if not doc_id.isdigit():
        print("  ❌ Nieprawidłowe ID")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("SELECT * FROM generated_documents WHERE id = %s", (int(doc_id),))
        doc = cur.fetchone()
        cur.close()
        conn.close()
        
        if not doc:
            print(f"  ⚠️ Nie znaleziono dokumentu o ID {doc_id}")
        else:
            print(f"\n  📄 DOKUMENT #{doc['id']}")
            print(f"  Imię: {doc['name']}")
            print(f"  Nazwisko: {doc['surname']}")
            print(f"  PESEL: {doc['pesel']}")
            print(f"  Token: {doc['view_token']}")
            print(f"  Data: {doc['created_at']}")
            print(f"\n  🔗 Link do dokumentu:")
            print(f"  https://generatordlagoatow123.up.railway.app/id.html?doc_id={doc['id']}&token={doc['view_token']}")
            
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def delete_document():
    """Usuń dokument"""
    print_header()
    print("\n🗑️ USUŃ DOKUMENT\n")
    
    doc_id = input("  ID dokumentu do usunięcia: ").strip()
    
    if not doc_id.isdigit():
        print("  ❌ Nieprawidłowe ID")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    confirm = input(f"  Czy na pewno usunąć dokument {doc_id}? (tak/nie): ").strip().lower()
    
    if confirm != 'tak':
        print("  ❌ Anulowano")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM generated_documents WHERE id = %s", (int(doc_id),))
        deleted = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        
        if deleted:
            print(f"\n  ✅ Dokument {doc_id} został usunięty")
        else:
            print(f"\n  ⚠️ Nie znaleziono dokumentu o ID {doc_id}")
            
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def delete_all_documents():
    """Usuń wszystkie dokumenty"""
    print_header()
    print("\n⚠️ USUŃ WSZYSTKIE DOKUMENTY\n")
    
    confirm = input("  Wpisz 'USUN DOKUMENTY' aby potwierdzić: ").strip()
    
    if confirm != 'USUN DOKUMENTY':
        print("  ❌ Anulowano")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM generated_documents")
        deleted = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"\n  ✅ Usunięto {deleted} dokumentów")
            
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def list_codes():
    """Lista kodów dostępu"""
    print_header()
    print("\n🔑 LISTA KODÓW (ostatnie 30)\n")
    
    try:
        conn = get_db()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT id, code, used, created_at, expires_at 
            FROM one_time_codes 
            ORDER BY created_at DESC 
            LIMIT 30
        """)
        codes = cur.fetchall()
        cur.close()
        conn.close()
        
        if not codes:
            print("  Brak kodów")
        else:
            print(f"  {'ID':<6} {'Kod':<15} {'Status':<12} {'Data utworzenia'}")
            print("  " + "-"*60)
            for c in codes:
                status = "✅ Użyty" if c['used'] else "🟢 Aktywny"
                date = c['created_at'].strftime("%Y-%m-%d %H:%M") if c['created_at'] else "-"
                print(f"  {c['id']:<6} {c['code']:<15} {status:<12} {date}")
                
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def generate_codes():
    """Generuj nowe kody"""
    print_header()
    print("\n🔑 GENERUJ NOWE KODY\n")
    
    import secrets
    import string
    
    try:
        count = int(input("  Ile kodów wygenerować? (1-100): ").strip())
        if count < 1 or count > 100:
            print("  ❌ Liczba musi być między 1 a 100")
            input("\n  Naciśnij Enter aby kontynuować...")
            return
    except ValueError:
        print("  ❌ Nieprawidłowa liczba")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    code_type = input("  Typ kodu (single/pack) [single]: ").strip() or 'single'
    
    try:
        conn = get_db()
        cur = conn.cursor()
        
        codes = []
        expires_at = None if code_type == 'pack' else datetime.utcnow() + timedelta(hours=72)
        
        for _ in range(count):
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
            cur.execute("INSERT INTO one_time_codes (code, expires_at, code_type) VALUES (%s, %s, %s)", 
                       (code, expires_at, code_type))
            codes.append(code)
        
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"\n  ✅ Wygenerowano {count} kodów:\n")
        for code in codes:
            print(f"  {code}")
            
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def delete_used_codes():
    """Usuń wykorzystane kody"""
    print_header()
    print("\n🗑️ USUŃ WYKORZYSTANE KODY\n")
    
    confirm = input("  Czy na pewno usunąć wykorzystane kody? (tak/nie): ").strip().lower()
    
    if confirm != 'tak':
        print("  ❌ Anulowano")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM one_time_codes WHERE used = TRUE")
        deleted = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"\n  ✅ Usunięto {deleted} wykorzystanych kodów")
            
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def delete_all_codes():
    """Usuń wszystkie kody"""
    print_header()
    print("\n⚠️ USUŃ WSZYSTKIE KODY\n")
    
    confirm = input("  Wpisz 'USUN KODY' aby potwierdzić: ").strip()
    
    if confirm != 'USUN KODY':
        print("  ❌ Anulowano")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM one_time_codes")
        deleted = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"\n  ✅ Usunięto {deleted} kodów")
            
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def panic_clear_all():
    """PANIC - Wyczyść całą bazę"""
    print_header()
    print("\n" + "!"*60)
    print("  ⚠️  UWAGA! NIEBEZPIECZNA OPERACJA!")
    print("!"*60)
    print("\n  Ta operacja USUNIE WSZYSTKIE DANE:")
    print("  - Wszystkie dokumenty")
    print("  - Wszystkie kody")
    print("  - Wszystkich użytkowników (oprócz adminów)")
    
    confirm = input("\n  Wpisz 'PANIC DELETE ALL' aby potwierdzić: ").strip()
    
    if confirm != 'PANIC DELETE ALL':
        print("  ❌ Anulowano")
        input("\n  Naciśnij Enter aby kontynuować...")
        return
    
    try:
        conn = get_db()
        cur = conn.cursor()
        
        cur.execute("DELETE FROM generated_documents")
        docs = cur.rowcount
        
        cur.execute("DELETE FROM one_time_codes")
        codes = cur.rowcount
        
        cur.execute("DELETE FROM users WHERE is_admin = FALSE")
        users = cur.rowcount
        
        conn.commit()
        cur.close()
        conn.close()
        
        print(f"\n  ✅ BAZA WYCZYSZCZONA:")
        print(f"     Dokumenty: {docs}")
        print(f"     Kody: {codes}")
        print(f"     Użytkownicy (nie-admini): {users}")
            
    except Exception as e:
        print(f"  ❌ Błąd: {e}")
    
    input("\n  Naciśnij Enter aby kontynuować...")

def main():
    """Główna pętla programu"""
    while True:
        print_header()
        print_menu()
        
        choice = input("  Wybierz opcję: ").strip()
        
        if choice == '0':
            print("\n  👋 Do widzenia!\n")
            sys.exit(0)
        elif choice == '1':
            show_stats()
        elif choice == '2':
            list_users()
        elif choice == '3':
            add_admin()
        elif choice == '4':
            delete_user()
        elif choice == '5':
            list_documents()
        elif choice == '6':
            search_document()
        elif choice == '7':
            delete_document()
        elif choice == '8':
            delete_all_documents()
        elif choice == '9':
            list_codes()
        elif choice == '10':
            generate_codes()
        elif choice == '11':
            delete_used_codes()
        elif choice == '12':
            delete_all_codes()
        elif choice == '13':
            panic_clear_all()
        else:
            print("  ❌ Nieprawidłowa opcja")
            input("\n  Naciśnij Enter aby kontynuować...")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  👋 Do widzenia!\n")
        sys.exit(0)

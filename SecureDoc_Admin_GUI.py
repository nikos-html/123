#!/usr/bin/env python3
"""
SecureDoc Admin Panel - Aplikacja GUI
"""

import os
import sys
import threading
import secrets
import string
from datetime import datetime, timedelta

# Instalacja bibliotek jeśli brakuje
def install_packages():
    packages = ['psycopg[binary]', 'bcrypt', 'customtkinter']
    for pkg in packages:
        try:
            if 'psycopg' in pkg:
                import psycopg
            elif 'bcrypt' in pkg:
                import bcrypt
            elif 'customtkinter' in pkg:
                import customtkinter
        except ImportError:
            print(f"Instaluję {pkg}...")
            os.system(f'pip install {pkg}')

install_packages()

import customtkinter as ctk
from tkinter import messagebox, simpledialog
import psycopg
from psycopg.rows import dict_row
import bcrypt

# ============================================================================
# KONFIGURACJA
# ============================================================================
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class DatabaseManager:
    def __init__(self, url):
        self.url = url
    
    def get_connection(self):
        return psycopg.connect(self.url)
    
    def test_connection(self):
        try:
            conn = self.get_connection()
            conn.close()
            return True
        except:
            return False
    
    def get_stats(self):
        conn = self.get_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT COUNT(*) FROM users")
        users = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM users WHERE is_admin = TRUE")
        admins = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM generated_documents")
        docs = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM one_time_codes WHERE used = FALSE")
        codes_active = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM one_time_codes WHERE used = TRUE")
        codes_used = cur.fetchone()[0]
        
        cur.close()
        conn.close()
        
        return {
            'users': users,
            'admins': admins,
            'documents': docs,
            'codes_active': codes_active,
            'codes_used': codes_used
        }
    
    def get_users(self):
        conn = self.get_connection()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("SELECT id, username, is_admin, has_access, created_at FROM users ORDER BY id DESC")
        users = cur.fetchall()
        cur.close()
        conn.close()
        return users
    
    def add_admin(self, username, password):
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (username, password, has_access, is_admin)
            VALUES (%s, %s, TRUE, TRUE)
            ON CONFLICT (username) DO UPDATE SET password = EXCLUDED.password, is_admin = TRUE
        """, (username, hashed))
        conn.commit()
        cur.close()
        conn.close()
    
    def delete_user(self, user_id):
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cur.close()
        conn.close()
    
    def get_documents(self):
        conn = self.get_connection()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT id, name, surname, pesel, view_token, created_at 
            FROM generated_documents ORDER BY created_at DESC LIMIT 100
        """)
        docs = cur.fetchall()
        cur.close()
        conn.close()
        return docs
    
    def delete_document(self, doc_id):
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM generated_documents WHERE id = %s", (doc_id,))
        conn.commit()
        cur.close()
        conn.close()
    
    def delete_all_documents(self):
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM generated_documents")
        count = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        return count
    
    def get_codes(self):
        conn = self.get_connection()
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT id, code, used, created_at, expires_at 
            FROM one_time_codes ORDER BY created_at DESC LIMIT 100
        """)
        codes = cur.fetchall()
        cur.close()
        conn.close()
        return codes
    
    def generate_codes(self, count, code_type='single'):
        conn = self.get_connection()
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
        return codes
    
    def delete_used_codes(self):
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM one_time_codes WHERE used = TRUE")
        count = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        return count
    
    def delete_all_codes(self):
        conn = self.get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM one_time_codes")
        count = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        return count
    
    def panic_delete(self):
        conn = self.get_connection()
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
        
        return {'docs': docs, 'codes': codes, 'users': users}


class LoginWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("SecureDoc Admin - Logowanie")
        self.geometry("500x350")
        self.resizable(False, False)
        
        # Center window
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 500) // 2
        y = (self.winfo_screenheight() - 350) // 2
        self.geometry(f"+{x}+{y}")
        
        self.db_manager = None
        
        self.create_widgets()
    
    def create_widgets(self):
        # Logo/Title
        title = ctk.CTkLabel(self, text="🔒 SecureDoc Admin", font=("Arial", 28, "bold"))
        title.pack(pady=(40, 10))
        
        subtitle = ctk.CTkLabel(self, text="Panel zarządzania bazą danych", font=("Arial", 14), text_color="gray")
        subtitle.pack(pady=(0, 30))
        
        # Frame for input
        frame = ctk.CTkFrame(self)
        frame.pack(padx=40, pady=10, fill="x")
        
        label = ctk.CTkLabel(frame, text="DATABASE_URL z Railway:", font=("Arial", 12))
        label.pack(pady=(15, 5), padx=20, anchor="w")
        
        self.url_entry = ctk.CTkEntry(frame, width=400, height=40, placeholder_text="postgresql://user:pass@host:port/db")
        self.url_entry.pack(pady=(0, 15), padx=20)
        
        # Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(pady=20)
        
        self.connect_btn = ctk.CTkButton(btn_frame, text="Połącz", width=150, height=40, 
                                          command=self.connect, font=("Arial", 14, "bold"))
        self.connect_btn.pack(side="left", padx=10)
        
        exit_btn = ctk.CTkButton(btn_frame, text="Wyjście", width=150, height=40,
                                  command=self.quit, fg_color="gray", font=("Arial", 14))
        exit_btn.pack(side="left", padx=10)
        
        # Status
        self.status_label = ctk.CTkLabel(self, text="", font=("Arial", 12))
        self.status_label.pack(pady=10)
    
    def connect(self):
        url = self.url_entry.get().strip()
        
        if not url:
            self.status_label.configure(text="❌ Podaj DATABASE_URL", text_color="red")
            return
        
        self.status_label.configure(text="⏳ Łączenie...", text_color="orange")
        self.connect_btn.configure(state="disabled")
        self.update()
        
        self.db_manager = DatabaseManager(url)
        
        if self.db_manager.test_connection():
            self.status_label.configure(text="✅ Połączono!", text_color="green")
            self.after(500, self.open_main_window)
        else:
            self.status_label.configure(text="❌ Nie można połączyć z bazą", text_color="red")
            self.connect_btn.configure(state="normal")
    
    def open_main_window(self):
        self.withdraw()
        main_window = MainWindow(self.db_manager, self)
        main_window.mainloop()


class MainWindow(ctk.CTkToplevel):
    def __init__(self, db_manager, parent):
        super().__init__(parent)
        
        self.db_manager = db_manager
        self.parent = parent
        
        self.title("SecureDoc Admin Panel")
        self.geometry("1100x700")
        self.minsize(900, 600)
        
        # Center window
        self.update_idletasks()
        x = (self.winfo_screenwidth() - 1100) // 2
        y = (self.winfo_screenheight() - 700) // 2
        self.geometry(f"+{x}+{y}")
        
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.create_widgets()
        self.refresh_stats()
    
    def on_close(self):
        self.parent.destroy()
    
    def create_widgets(self):
        # Sidebar
        sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        
        # Logo
        logo = ctk.CTkLabel(sidebar, text="🔒 SecureDoc", font=("Arial", 20, "bold"))
        logo.pack(pady=(20, 5))
        
        admin_label = ctk.CTkLabel(sidebar, text="Admin Panel", font=("Arial", 12), text_color="gray")
        admin_label.pack(pady=(0, 30))
        
        # Menu buttons
        self.menu_buttons = []
        
        menus = [
            ("📊 Dashboard", self.show_dashboard),
            ("👥 Użytkownicy", self.show_users),
            ("📄 Dokumenty", self.show_documents),
            ("🔑 Kody", self.show_codes),
            ("⚠️ PANIC", self.show_panic),
        ]
        
        for text, command in menus:
            btn = ctk.CTkButton(sidebar, text=text, width=180, height=40, 
                               command=command, anchor="w", font=("Arial", 13))
            btn.pack(pady=5, padx=10)
            self.menu_buttons.append(btn)
        
        # Spacer
        spacer = ctk.CTkLabel(sidebar, text="")
        spacer.pack(expand=True)
        
        # Exit button
        exit_btn = ctk.CTkButton(sidebar, text="🚪 Wyjście", width=180, height=40,
                                  command=self.on_close, fg_color="gray", font=("Arial", 13))
        exit_btn.pack(pady=20, padx=10)
        
        # Main content area
        self.content = ctk.CTkFrame(self)
        self.content.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # Show dashboard by default
        self.show_dashboard()
    
    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()
    
    def refresh_stats(self):
        try:
            self.stats = self.db_manager.get_stats()
        except Exception as e:
            messagebox.showerror("Błąd", f"Nie można pobrać statystyk: {e}")
            self.stats = {}
    
    def show_dashboard(self):
        self.clear_content()
        self.refresh_stats()
        
        title = ctk.CTkLabel(self.content, text="📊 Dashboard", font=("Arial", 24, "bold"))
        title.pack(pady=(20, 30), anchor="w", padx=20)
        
        # Stats cards
        cards_frame = ctk.CTkFrame(self.content, fg_color="transparent")
        cards_frame.pack(fill="x", padx=20)
        
        stats_data = [
            ("👥 Użytkownicy", self.stats.get('users', 0), "#3498db"),
            ("👑 Admini", self.stats.get('admins', 0), "#9b59b6"),
            ("📄 Dokumenty", self.stats.get('documents', 0), "#2ecc71"),
            ("🔑 Kody aktywne", self.stats.get('codes_active', 0), "#e74c3c"),
            ("✅ Kody użyte", self.stats.get('codes_used', 0), "#95a5a6"),
        ]
        
        for i, (label, value, color) in enumerate(stats_data):
            card = ctk.CTkFrame(cards_frame, width=160, height=120)
            card.grid(row=0, column=i, padx=10, pady=10)
            card.grid_propagate(False)
            
            val_label = ctk.CTkLabel(card, text=str(value), font=("Arial", 36, "bold"), text_color=color)
            val_label.pack(pady=(25, 5))
            
            name_label = ctk.CTkLabel(card, text=label, font=("Arial", 12))
            name_label.pack()
        
        # Refresh button
        refresh_btn = ctk.CTkButton(self.content, text="🔄 Odśwież", width=120, 
                                     command=self.show_dashboard)
        refresh_btn.pack(pady=30)
    
    def show_users(self):
        self.clear_content()
        
        # Header
        header = ctk.CTkFrame(self.content, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        
        title = ctk.CTkLabel(header, text="👥 Użytkownicy", font=("Arial", 24, "bold"))
        title.pack(side="left")
        
        add_btn = ctk.CTkButton(header, text="➕ Dodaj admina", width=140, 
                                 command=self.add_admin_dialog)
        add_btn.pack(side="right")
        
        # Table
        table_frame = ctk.CTkScrollableFrame(self.content, height=400)
        table_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Headers
        headers = ["ID", "Username", "Admin", "Dostęp", "Data", "Akcje"]
        for i, h in enumerate(headers):
            lbl = ctk.CTkLabel(table_frame, text=h, font=("Arial", 12, "bold"))
            lbl.grid(row=0, column=i, padx=10, pady=10, sticky="w")
        
        try:
            users = self.db_manager.get_users()
            for row, user in enumerate(users, 1):
                ctk.CTkLabel(table_frame, text=str(user['id'])).grid(row=row, column=0, padx=10, pady=5, sticky="w")
                ctk.CTkLabel(table_frame, text=user['username']).grid(row=row, column=1, padx=10, pady=5, sticky="w")
                ctk.CTkLabel(table_frame, text="✅" if user['is_admin'] else "❌").grid(row=row, column=2, padx=10, pady=5)
                ctk.CTkLabel(table_frame, text="✅" if user['has_access'] else "❌").grid(row=row, column=3, padx=10, pady=5)
                date = user['created_at'].strftime("%Y-%m-%d") if user['created_at'] else "-"
                ctk.CTkLabel(table_frame, text=date).grid(row=row, column=4, padx=10, pady=5, sticky="w")
                
                del_btn = ctk.CTkButton(table_frame, text="🗑️", width=40, fg_color="red",
                                         command=lambda uid=user['id']: self.delete_user(uid))
                del_btn.grid(row=row, column=5, padx=10, pady=5)
        except Exception as e:
            messagebox.showerror("Błąd", str(e))
    
    def add_admin_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Dodaj administratora")
        dialog.geometry("400x250")
        dialog.resizable(False, False)
        dialog.grab_set()
        
        ctk.CTkLabel(dialog, text="Username:", font=("Arial", 12)).pack(pady=(20, 5))
        username_entry = ctk.CTkEntry(dialog, width=300)
        username_entry.pack()
        
        ctk.CTkLabel(dialog, text="Hasło:", font=("Arial", 12)).pack(pady=(15, 5))
        password_entry = ctk.CTkEntry(dialog, width=300, show="*")
        password_entry.pack()
        
        def save():
            username = username_entry.get().strip()
            password = password_entry.get()
            
            if not username or not password:
                messagebox.showerror("Błąd", "Wypełnij wszystkie pola")
                return
            
            try:
                self.db_manager.add_admin(username, password)
                messagebox.showinfo("Sukces", f"Admin '{username}' został dodany")
                dialog.destroy()
                self.show_users()
            except Exception as e:
                messagebox.showerror("Błąd", str(e))
        
        ctk.CTkButton(dialog, text="Zapisz", width=200, command=save).pack(pady=30)
    
    def delete_user(self, user_id):
        if messagebox.askyesno("Potwierdzenie", f"Czy na pewno usunąć użytkownika {user_id}?"):
            try:
                self.db_manager.delete_user(user_id)
                messagebox.showinfo("Sukces", "Użytkownik usunięty")
                self.show_users()
            except Exception as e:
                messagebox.showerror("Błąd", str(e))
    
    def show_documents(self):
        self.clear_content()
        
        # Header
        header = ctk.CTkFrame(self.content, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        
        title = ctk.CTkLabel(header, text="📄 Dokumenty", font=("Arial", 24, "bold"))
        title.pack(side="left")
        
        del_all_btn = ctk.CTkButton(header, text="🗑️ Usuń wszystkie", width=140, 
                                     fg_color="red", command=self.delete_all_documents)
        del_all_btn.pack(side="right")
        
        # Table
        table_frame = ctk.CTkScrollableFrame(self.content, height=450)
        table_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        headers = ["ID", "Imię", "Nazwisko", "PESEL", "Data", "Akcje"]
        for i, h in enumerate(headers):
            lbl = ctk.CTkLabel(table_frame, text=h, font=("Arial", 12, "bold"))
            lbl.grid(row=0, column=i, padx=10, pady=10, sticky="w")
        
        try:
            docs = self.db_manager.get_documents()
            for row, doc in enumerate(docs, 1):
                ctk.CTkLabel(table_frame, text=str(doc['id'])).grid(row=row, column=0, padx=10, pady=5, sticky="w")
                ctk.CTkLabel(table_frame, text=doc['name'] or '-').grid(row=row, column=1, padx=10, pady=5, sticky="w")
                ctk.CTkLabel(table_frame, text=doc['surname'] or '-').grid(row=row, column=2, padx=10, pady=5, sticky="w")
                ctk.CTkLabel(table_frame, text=doc['pesel'] or '-').grid(row=row, column=3, padx=10, pady=5, sticky="w")
                date = doc['created_at'].strftime("%Y-%m-%d %H:%M") if doc['created_at'] else "-"
                ctk.CTkLabel(table_frame, text=date).grid(row=row, column=4, padx=10, pady=5, sticky="w")
                
                btn_frame = ctk.CTkFrame(table_frame, fg_color="transparent")
                btn_frame.grid(row=row, column=5, padx=5, pady=5)
                
                view_btn = ctk.CTkButton(btn_frame, text="👁️", width=35,
                                          command=lambda d=doc: self.view_document(d))
                view_btn.pack(side="left", padx=2)
                
                del_btn = ctk.CTkButton(btn_frame, text="🗑️", width=35, fg_color="red",
                                         command=lambda did=doc['id']: self.delete_document(did))
                del_btn.pack(side="left", padx=2)
        except Exception as e:
            messagebox.showerror("Błąd", str(e))
    
    def view_document(self, doc):
        url = f"https://generatordlagoatow123.up.railway.app/id.html?doc_id={doc['id']}&token={doc['view_token']}"
        
        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Dokument #{doc['id']}")
        dialog.geometry("600x300")
        dialog.grab_set()
        
        info = f"""
        ID: {doc['id']}
        Imię: {doc['name']}
        Nazwisko: {doc['surname']}
        PESEL: {doc['pesel']}
        Token: {doc['view_token']}
        """
        
        ctk.CTkLabel(dialog, text=info, font=("Arial", 14), justify="left").pack(pady=20)
        
        ctk.CTkLabel(dialog, text="Link do dokumentu:", font=("Arial", 12, "bold")).pack()
        
        url_entry = ctk.CTkEntry(dialog, width=550)
        url_entry.pack(pady=10)
        url_entry.insert(0, url)
        
        def copy_url():
            self.clipboard_clear()
            self.clipboard_append(url)
            messagebox.showinfo("Skopiowano", "Link skopiowany do schowka!")
        
        ctk.CTkButton(dialog, text="📋 Kopiuj link", command=copy_url).pack(pady=10)
    
    def delete_document(self, doc_id):
        if messagebox.askyesno("Potwierdzenie", f"Czy na pewno usunąć dokument {doc_id}?"):
            try:
                self.db_manager.delete_document(doc_id)
                messagebox.showinfo("Sukces", "Dokument usunięty")
                self.show_documents()
            except Exception as e:
                messagebox.showerror("Błąd", str(e))
    
    def delete_all_documents(self):
        if messagebox.askyesno("⚠️ UWAGA", "Czy na pewno usunąć WSZYSTKIE dokumenty?\n\nTa operacja jest nieodwracalna!"):
            try:
                count = self.db_manager.delete_all_documents()
                messagebox.showinfo("Sukces", f"Usunięto {count} dokumentów")
                self.show_documents()
            except Exception as e:
                messagebox.showerror("Błąd", str(e))
    
    def show_codes(self):
        self.clear_content()
        
        # Header
        header = ctk.CTkFrame(self.content, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        
        title = ctk.CTkLabel(header, text="🔑 Kody dostępu", font=("Arial", 24, "bold"))
        title.pack(side="left")
        
        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right")
        
        gen_btn = ctk.CTkButton(btn_frame, text="➕ Generuj", width=100, 
                                 command=self.generate_codes_dialog)
        gen_btn.pack(side="left", padx=5)
        
        del_used_btn = ctk.CTkButton(btn_frame, text="🗑️ Usuń użyte", width=120, 
                                      fg_color="orange", command=self.delete_used_codes)
        del_used_btn.pack(side="left", padx=5)
        
        del_all_btn = ctk.CTkButton(btn_frame, text="🗑️ Usuń wszystkie", width=130, 
                                     fg_color="red", command=self.delete_all_codes)
        del_all_btn.pack(side="left", padx=5)
        
        # Table
        table_frame = ctk.CTkScrollableFrame(self.content, height=450)
        table_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        headers = ["ID", "Kod", "Status", "Data utworzenia"]
        for i, h in enumerate(headers):
            lbl = ctk.CTkLabel(table_frame, text=h, font=("Arial", 12, "bold"))
            lbl.grid(row=0, column=i, padx=15, pady=10, sticky="w")
        
        try:
            codes = self.db_manager.get_codes()
            for row, code in enumerate(codes, 1):
                ctk.CTkLabel(table_frame, text=str(code['id'])).grid(row=row, column=0, padx=15, pady=5, sticky="w")
                
                code_label = ctk.CTkLabel(table_frame, text=code['code'], font=("Courier", 12))
                code_label.grid(row=row, column=1, padx=15, pady=5, sticky="w")
                
                status = "✅ Użyty" if code['used'] else "🟢 Aktywny"
                status_color = "gray" if code['used'] else "green"
                ctk.CTkLabel(table_frame, text=status, text_color=status_color).grid(row=row, column=2, padx=15, pady=5, sticky="w")
                
                date = code['created_at'].strftime("%Y-%m-%d %H:%M") if code['created_at'] else "-"
                ctk.CTkLabel(table_frame, text=date).grid(row=row, column=3, padx=15, pady=5, sticky="w")
        except Exception as e:
            messagebox.showerror("Błąd", str(e))
    
    def generate_codes_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Generuj kody")
        dialog.geometry("400x300")
        dialog.resizable(False, False)
        dialog.grab_set()
        
        ctk.CTkLabel(dialog, text="Ile kodów wygenerować?", font=("Arial", 14)).pack(pady=(30, 10))
        
        count_entry = ctk.CTkEntry(dialog, width=200, placeholder_text="1-100")
        count_entry.pack()
        count_entry.insert(0, "10")
        
        ctk.CTkLabel(dialog, text="Typ kodu:", font=("Arial", 14)).pack(pady=(20, 10))
        
        code_type = ctk.StringVar(value="single")
        ctk.CTkRadioButton(dialog, text="Jednorazowy (72h)", variable=code_type, value="single").pack()
        ctk.CTkRadioButton(dialog, text="Pakiet (bez limitu)", variable=code_type, value="pack").pack(pady=5)
        
        def generate():
            try:
                count = int(count_entry.get())
                if count < 1 or count > 100:
                    raise ValueError()
            except:
                messagebox.showerror("Błąd", "Podaj liczbę 1-100")
                return
            
            try:
                codes = self.db_manager.generate_codes(count, code_type.get())
                
                # Show codes in new window
                codes_window = ctk.CTkToplevel(self)
                codes_window.title(f"Wygenerowane kody ({len(codes)})")
                codes_window.geometry("400x500")
                
                text = ctk.CTkTextbox(codes_window, width=380, height=400)
                text.pack(pady=20, padx=10)
                text.insert("1.0", "\n".join(codes))
                
                def copy_all():
                    self.clipboard_clear()
                    self.clipboard_append("\n".join(codes))
                    messagebox.showinfo("Skopiowano", "Kody skopiowane do schowka!")
                
                ctk.CTkButton(codes_window, text="📋 Kopiuj wszystkie", command=copy_all).pack()
                
                dialog.destroy()
                self.show_codes()
            except Exception as e:
                messagebox.showerror("Błąd", str(e))
        
        ctk.CTkButton(dialog, text="Generuj", width=200, command=generate).pack(pady=30)
    
    def delete_used_codes(self):
        if messagebox.askyesno("Potwierdzenie", "Usunąć wszystkie wykorzystane kody?"):
            try:
                count = self.db_manager.delete_used_codes()
                messagebox.showinfo("Sukces", f"Usunięto {count} kodów")
                self.show_codes()
            except Exception as e:
                messagebox.showerror("Błąd", str(e))
    
    def delete_all_codes(self):
        if messagebox.askyesno("⚠️ UWAGA", "Czy na pewno usunąć WSZYSTKIE kody?"):
            try:
                count = self.db_manager.delete_all_codes()
                messagebox.showinfo("Sukces", f"Usunięto {count} kodów")
                self.show_codes()
            except Exception as e:
                messagebox.showerror("Błąd", str(e))
    
    def show_panic(self):
        self.clear_content()
        
        title = ctk.CTkLabel(self.content, text="⚠️ PANIC MODE", font=("Arial", 28, "bold"), text_color="red")
        title.pack(pady=(50, 20))
        
        warning = ctk.CTkLabel(self.content, text="""
        Ta opcja USUNIE WSZYSTKIE DANE:
        
        • Wszystkie dokumenty
        • Wszystkie kody dostępu  
        • Wszystkich użytkowników (oprócz adminów)
        
        Ta operacja jest NIEODWRACALNA!
        """, font=("Arial", 14), justify="center")
        warning.pack(pady=20)
        
        panic_btn = ctk.CTkButton(self.content, text="🚨 WYCZYŚĆ WSZYSTKO", width=250, height=50,
                                   fg_color="red", hover_color="darkred", font=("Arial", 16, "bold"),
                                   command=self.panic_delete)
        panic_btn.pack(pady=30)
    
    def panic_delete(self):
        result = messagebox.askquestion("⚠️ OSTATNIE OSTRZEŻENIE", 
                                        "CZY NA PEWNO CHCESZ USUNĄĆ WSZYSTKIE DANE?\n\nTa operacja jest NIEODWRACALNA!",
                                        icon='warning')
        if result == 'yes':
            confirm = simpledialog.askstring("Potwierdzenie", "Wpisz 'USUN' aby potwierdzić:")
            if confirm == "USUN":
                try:
                    result = self.db_manager.panic_delete()
                    messagebox.showinfo("Gotowe", f"Usunięto:\n• Dokumenty: {result['docs']}\n• Kody: {result['codes']}\n• Użytkownicy: {result['users']}")
                    self.show_dashboard()
                except Exception as e:
                    messagebox.showerror("Błąd", str(e))
            else:
                messagebox.showinfo("Anulowano", "Operacja anulowana")


if __name__ == '__main__':
    app = LoginWindow()
    app.mainloop()

import os
import json
import base64
import secrets
import string
import time
import customtkinter as ctk
from tkinter import messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_FILE = "safe_code.vault"
SETTINGS_FILE = "safe_code_settings.json"
ITERATIONS = 600000

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {"lock_timeout": 300}

def save_settings(settings):
    with open(SETTINGS_FILE, 'w') as f:
        json.dump(settings, f)

class SafeCodeManager:
    def __init__(self):
        self.vault_data = {}
        self.salt = None
        self.key = None
        self.last_activity = time.time()

    def update_activity(self):
        self.last_activity = time.time()

    def _derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
        )
        return kdf.derive(password.encode())

    def create_vault(self, master_password):
        if os.path.exists(VAULT_FILE):
            return False
        self.salt = os.urandom(16)
        self.key = self._derive_key(master_password, self.salt)
        self.vault_data = {}
        self._save_vault()
        return True

    def unlock_vault(self, master_password):
        if not os.path.exists(VAULT_FILE):
            return False
        with open(VAULT_FILE, 'rb') as f:
            file_data = json.load(f)
        self.salt = base64.b64decode(file_data['salt'])
        self.key = self._derive_key(master_password, self.salt)
        try:
            encrypted_data = base64.b64decode(file_data['data'])
            aesgcm = AESGCM(self.key)
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            self.vault_data = json.loads(decrypted_bytes.decode())
            self.last_activity = time.time()
            return True
        except Exception:
            self.key = None
            return False

    def _save_vault(self):
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)
        plaintext = json.dumps(self.vault_data).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        encrypted_blob = nonce + ciphertext
        file_data = {
            'salt': base64.b64encode(self.salt).decode(),
            'data': base64.b64encode(encrypted_blob).decode()
        }
        with open(VAULT_FILE, 'w') as f:
            json.dump(file_data, f)

    def add_password(self, service, username, password, category="Autre", notes=""):
        self.vault_data[service] = {
            "user": username,
            "pass": password,
            "category": category,
            "notes": notes
        }
        self._save_vault()

    def update_password(self, service, username, password, category="Autre", notes=""):
        if service in self.vault_data:
            self.vault_data[service] = {
                "user": username,
                "pass": password,
                "category": category,
                "notes": notes
            }
            self._save_vault()

    def get_password(self, service):
        return self.vault_data.get(service)

    def delete_password(self, service):
        if service in self.vault_data:
            del self.vault_data[service]
            self._save_vault()
            return True
        return False

    def change_master_password(self, old_password, new_password):
        if not self.unlock_vault(old_password):
            return False, "Ancien mot de passe incorrect"
        if len(new_password) < 8:
            return False, "Le nouveau mot de passe doit faire au moins 8 caracteres"
        new_salt = os.urandom(16)
        new_key = self._derive_key(new_password, new_salt)
        old_key = self.key
        old_salt = self.salt
        self.key = new_key
        self.salt = new_salt
        try:
            self._save_vault()
            return True, "Mot de passe maitre change avec succes !"
        except Exception as e:
            self.key = old_key
            self.salt = old_salt
            return False, f"Erreur lors du changement : {e}"

    def list_services(self):
        return list(self.vault_data.keys())

    def search_services(self, query):
        query = query.lower()
        results = []
        for service, data in self.vault_data.items():
            if (query in service.lower() or
                query in data.get("user", "").lower() or
                query in data.get("category", "").lower() or
                query in data.get("notes", "").lower()):
                results.append(service)
        return results

    def get_categories(self):
        categories = set()
        for data in self.vault_data.values():
            categories.add(data.get("category", "Autre"))
        return sorted(list(categories))

    def filter_by_category(self, category):
        if category == "Tous":
            return self.list_services()
        return [s for s, data in self.vault_data.items() if data.get("category", "Autre") == category]

    def check_duplicate_passwords(self):
        passwords = {}
        for service, data in self.vault_data.items():
            pwd = data["pass"]
            if pwd not in passwords:
                passwords[pwd] = []
            passwords[pwd].append(service)
        return {pwd: services for pwd, services in passwords.items() if len(services) > 1}

    @staticmethod
    def check_password_strength(password):
        score = 0
        if len(password) >= 12: score += 1
        if len(password) >= 16: score += 1
        if any(c.isupper() for c in password): score += 1
        if any(c.islower() for c in password): score += 1
        if any(c.isdigit() for c in password): score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password): score += 1
        if score <= 2: return "Faible", "#FF4444"
        elif score <= 4: return "Moyen", "#FFA500"
        else: return "Fort", "#00CC00"

    @staticmethod
    def generate_password(length=20, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True):
        if length < 8:
            length = 8
        alphabet = ""
        if use_uppercase: alphabet += string.ascii_uppercase
        if use_lowercase: alphabet += string.ascii_lowercase
        if use_digits: alphabet += string.digits
        if use_symbols: alphabet += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not alphabet: return ""
        return ''.join(secrets.choice(alphabet) for _ in range(length))


class SafeCodeApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Safe Code - Gestionnaire de Mots de Passe")
        self.geometry("1000x700")
        self.resizable(True, True)
        self.manager = SafeCodeManager()
        self.current_filter = "Tous"
        self.settings = load_settings()
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.show_login_screen()
        self.check_inactivity_loop()

    def check_inactivity_loop(self):
        timeout = self.settings.get("lock_timeout", 300)
        if timeout > 0 and self.manager.key is not None:
            if time.time() - self.manager.last_activity > timeout:
                messagebox.showwarning("Inactivite", "Coffre verrouille automatiquement")
                self.lock_vault(ask_confirmation=False)
        self.after(10000, self.check_inactivity_loop)

    def clear_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self.clear_screen()
        frame = ctk.CTkFrame(self, corner_radius=20)
        frame.pack(expand=True, fill="both", padx=100, pady=100)
        title_lbl = ctk.CTkLabel(frame, text="SAFE CODE", font=ctk.CTkFont(size=42, weight="bold"))
        title_lbl.pack(pady=(40, 10))
        sub_lbl = ctk.CTkLabel(frame, text="Gestionnaire Securise", font=ctk.CTkFont(size=16), text_color="gray")
        sub_lbl.pack(pady=(0, 40))
        pwd_lbl = ctk.CTkLabel(frame, text="Mot de passe maitre :", font=ctk.CTkFont(size=14))
        pwd_lbl.pack(pady=(10, 5))
        self.master_pwd_entry = ctk.CTkEntry(frame, show="*", width=350, height=40, font=ctk.CTkFont(size=16))
        self.master_pwd_entry.pack(pady=(0, 30))
        self.master_pwd_entry.bind("<Return>", lambda e: self.on_login())
        self.master_pwd_entry.focus()
        if os.path.exists(VAULT_FILE):
            btn = ctk.CTkButton(frame, text="Deverrouiller", width=250, height=45,
                                font=ctk.CTkFont(size=16, weight="bold"), command=self.on_login)
            btn.pack(pady=10)
        else:
            btn = ctk.CTkButton(frame, text="Creer le coffre", width=250, height=45,
                                font=ctk.CTkFont(size=16, weight="bold"), command=self.on_create_vault)
            btn.pack(pady=10)

    def on_create_vault(self):
        master_pwd = self.master_pwd_entry.get()
        if len(master_pwd) < 8:
            messagebox.showerror("Erreur", "Le mot de passe maitre doit faire au moins 8 caracteres")
            return
        confirm_window = ctk.CTkToplevel(self)
        confirm_window.title("Confirmation")
        confirm_window.geometry("450x250")
        confirm_window.transient(self)
        confirm_window.grab_set()
        lbl = ctk.CTkLabel(confirm_window, text="Confirmez le mot de passe maitre :", font=ctk.CTkFont(size=16))
        lbl.pack(pady=30)
        confirm_entry = ctk.CTkEntry(confirm_window, show="*", width=300, height=40, font=ctk.CTkFont(size=16))
        confirm_entry.pack(pady=10)
        def confirm():
            if confirm_entry.get() == master_pwd:
                if self.manager.create_vault(master_pwd):
                    messagebox.showinfo("Succes", "Coffre cree avec succes !")
                    confirm_window.destroy()
                    self.show_main_screen()
                else:
                    messagebox.showerror("Erreur", "Impossible de creer le coffre")
            else:
                messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas")
        btn = ctk.CTkButton(confirm_window, text="Confirmer", width=200, height=40,
                            font=ctk.CTkFont(size=14), command=confirm)
        btn.pack(pady=20)

    def on_login(self):
        master_pwd = self.master_pwd_entry.get()
        if self.manager.unlock_vault(master_pwd):
            self.show_main_screen()
        else:
            messagebox.showerror("Erreur", "Mot de passe maitre incorrect")
            self.master_pwd_entry.delete(0, "end")

    def show_main_screen(self):
        self.clear_screen()
        main_frame = ctk.CTkFrame(self, corner_radius=0)
        main_frame.pack(expand=True, fill="both")
        header_frame = ctk.CTkFrame(main_frame, height=80, corner_radius=0)
        header_frame.pack(fill="x")
        header_frame.pack_propagate(False)
        title_lbl = ctk.CTkLabel(header_frame, text="Mes Mots de Passe", font=ctk.CTkFont(size=28, weight="bold"))
        title_lbl.pack(side="left", padx=30, pady=20)
        btn_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_frame.pack(side="right", padx=30)
        ctk.CTkButton(btn_frame, text="+ Ajouter", width=120, height=40,
                      font=ctk.CTkFont(size=14, weight="bold"), command=self.show_add_dialog).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Generer", width=110, height=40,
                      font=ctk.CTkFont(size=14), command=self.show_generator_dialog).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Changer MDP", width=120, height=40,
                      font=ctk.CTkFont(size=14), fg_color="#FF8C00", hover_color="#CC7000",
                      command=self.show_change_password_dialog).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Parametres", width=110, height=40,
                      font=ctk.CTkFont(size=14), fg_color="#555555", hover_color="#444444",
                      command=self.show_settings_dialog).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Verrouiller", width=110, height=40,
                      font=ctk.CTkFont(size=14), fg_color="#CC0000", hover_color="#990000",
                      command=self.lock_vault).pack(side="left", padx=5)
        content_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        content_frame.pack(expand=True, fill="both", padx=20, pady=20)
        sidebar = ctk.CTkFrame(content_frame, width=200, corner_radius=10)
        sidebar.pack(side="left", fill="y", padx=(0, 20))
        sidebar.pack_propagate(False)
        cat_lbl = ctk.CTkLabel(sidebar, text="Categories", font=ctk.CTkFont(size=16, weight="bold"))
        cat_lbl.pack(pady=20)
        self.category_buttons = {}
        categories = ["Tous"] + self.manager.get_categories()
        for cat in categories:
            btn = ctk.CTkButton(sidebar, text=cat, width=160, height=35,
                                font=ctk.CTkFont(size=13), command=lambda c=cat: self.filter_category(c))
            btn.pack(pady=5, padx=20)
            self.category_buttons[cat] = btn
        main_content = ctk.CTkFrame(content_frame, corner_radius=10)
        main_content.pack(side="left", expand=True, fill="both")
        search_frame = ctk.CTkFrame(main_content, fg_color="transparent")
        search_frame.pack(fill="x", padx=20, pady=20)
        self.search_var = ctk.StringVar()
        self.search_var.trace("w", lambda name, index, mode: self.on_search_change())
        ctk.CTkEntry(search_frame, textvariable=self.search_var, placeholder_text="Rechercher...",
                     width=400, height=40, font=ctk.CTkFont(size=14)).pack(side="left", padx=(0, 10))
        self.duplicates_label = ctk.CTkLabel(search_frame, text="", font=ctk.CTkFont(size=12), text_color="#FFA500")
        self.duplicates_label.pack(side="right")
        self.check_duplicates()
        self.services_scroll = ctk.CTkScrollableFrame(main_content)
        self.services_scroll.pack(expand=True, fill="both", padx=20, pady=(0, 20))
        self.refresh_services_list()

    def on_search_change(self):
        self.refresh_services_list()

    def filter_category(self, category):
        self.current_filter = category
        for cat, btn in self.category_buttons.items():
            if cat == category:
                btn.configure(fg_color="#1F6AA5", hover_color="#1A5A8F")
            else:
                btn.configure(fg_color=None, hover_color=None)
        self.refresh_services_list()

    def check_duplicates(self):
        duplicates = self.manager.check_duplicate_passwords()
        if duplicates:
            count = sum(len(services) for services in duplicates.values())
            txt = f"Attention : {count} mots de passe dupliques"
            self.duplicates_label.configure(text=txt, text_color="#FFA500")
        else:
            self.duplicates_label.configure(text="")

    def refresh_services_list(self):
        for widget in self.services_scroll.winfo_children():
            widget.destroy()
        query = self.search_var.get()
        if query:
            services = self.manager.search_services(query)
        elif self.current_filter != "Tous":
            services = self.manager.filter_by_category(self.current_filter)
        else:
            services = self.manager.list_services()
        if not services:
            lbl = ctk.CTkLabel(self.services_scroll, text="Aucun service trouve",
                               font=ctk.CTkFont(size=16), text_color="gray")
            lbl.pack(pady=60)
            return
        for service in sorted(services):
            data = self.manager.get_password(service)
            service_frame = ctk.CTkFrame(self.services_scroll, corner_radius=8)
            service_frame.pack(fill="x", pady=8, padx=10)
            info_frame = ctk.CTkFrame(service_frame, fg_color="transparent")
            info_frame.pack(side="left", fill="x", expand=True, padx=20, pady=15)
            name_lbl = ctk.CTkLabel(info_frame, text=service, font=ctk.CTkFont(size=18, weight="bold"))
            name_lbl.pack(anchor="w")
            info_text = f"{data.get('user', '')} | {data.get('category', 'Autre')}"
            info_lbl = ctk.CTkLabel(info_frame, text=info_text, font=ctk.CTkFont(size=13), text_color="gray")
            info_lbl.pack(anchor="w")
            btn_frame = ctk.CTkFrame(service_frame, fg_color="transparent")
            btn_frame.pack(side="right", padx=20)
            ctk.CTkButton(btn_frame, text="Voir", width=75, height=35, font=ctk.CTkFont(size=12),
                          command=lambda s=service: self.show_password_dialog(s)).pack(side="left", padx=3)
            ctk.CTkButton(btn_frame, text="Modifier", width=80, height=35, font=ctk.CTkFont(size=12),
                          fg_color="#FF8C00", hover_color="#CC7000",
                          command=lambda s=service: self.show_edit_dialog(s)).pack(side="left", padx=3)
            ctk.CTkButton(btn_frame, text="Supprimer", width=85, height=35, font=ctk.CTkFont(size=12),
                          fg_color="#CC0000", hover_color="#990000",
                          command=lambda s=service: self.delete_service(s)).pack(side="left", padx=3)

    def show_add_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Ajouter un mot de passe")
        dialog.geometry("550x650")
        dialog.transient(self)
        dialog.grab_set()
        title_lbl = ctk.CTkLabel(dialog, text="Ajouter un service", font=ctk.CTkFont(size=24, weight="bold"))
        title_lbl.pack(pady=(20, 15))
        ctk.CTkLabel(dialog, text="Service :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        service_entry = ctk.CTkEntry(dialog, width=450, height=35)
        service_entry.pack(pady=(0, 10), padx=40)
        ctk.CTkLabel(dialog, text="Utilisateur / Email :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        username_entry = ctk.CTkEntry(dialog, width=450, height=35)
        username_entry.pack(pady=(0, 10), padx=40)
        ctk.CTkLabel(dialog, text="Mot de passe :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        password_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        password_frame.pack(pady=(0, 5), padx=40)
        password_entry = ctk.CTkEntry(password_frame, show="*", width=320, height=35)
        password_entry.pack(side="left", padx=(0, 10))
        def generate_and_fill():
            pwd = SafeCodeManager.generate_password()
            password_entry.delete(0, "end")
            password_entry.insert(0, pwd)
            update_strength(pwd)
        gen_btn = ctk.CTkButton(password_frame, text="Generer", width=120, height=35, command=generate_and_fill)
        gen_btn.pack(side="left")
        strength_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        strength_frame.pack(pady=(0, 10), padx=40, fill="x")
        strength_label = ctk.CTkLabel(strength_frame, text="Force : ", font=ctk.CTkFont(size=12))
        strength_label.pack(side="left")
        strength_bar = ctk.CTkProgressBar(strength_frame, width=300, height=8)
        strength_bar.pack(side="left", padx=10)
        strength_bar.set(0)
        def update_strength(pwd):
            strength, color = SafeCodeManager.check_password_strength(pwd)
            strength_label.configure(text=f"Force : {strength}", text_color=color)
            if strength == "Faible":
                strength_bar.set(0.33)
                strength_bar.configure(progress_color="#FF4444")
            elif strength == "Moyen":
                strength_bar.set(0.66)
                strength_bar.configure(progress_color="#FFA500")
            else:
                strength_bar.set(1.0)
                strength_bar.configure(progress_color="#00CC00")
        password_entry.bind("<KeyRelease>", lambda e: update_strength(password_entry.get()))
        ctk.CTkLabel(dialog, text="Categorie :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        category_entry = ctk.CTkEntry(dialog, width=450, height=35, placeholder_text="Ex: Travail, Perso, Banque...")
        category_entry.pack(pady=(0, 10), padx=40)
        ctk.CTkLabel(dialog, text="Notes :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        notes_entry = ctk.CTkTextbox(dialog, width=450, height=70)
        notes_entry.pack(pady=(0, 15), padx=40)
        def save():
            service = service_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get()
            category = category_entry.get().strip() or "Autre"
            notes = notes_entry.get("1.0", "end-1c").strip()
            if not service or not username or not password:
                messagebox.showerror("Erreur", "Service, utilisateur et mot de passe obligatoires")
                return
            self.manager.add_password(service, username, password, category, notes)
            self.refresh_services_list()
            self.check_duplicates()
            dialog.destroy()
            messagebox.showinfo("Succes", f"Mot de passe ajoute pour {service}")
        save_btn = ctk.CTkButton(dialog, text="Enregistrer", width=250, height=45,
                                 font=ctk.CTkFont(size=15, weight="bold"), command=save)
        save_btn.pack(pady=(10, 20))

    def show_edit_dialog(self, service):
        data = self.manager.get_password(service)
        if not data: return
        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Modifier {service}")
        dialog.geometry("550x650")
        dialog.transient(self)
        dialog.grab_set()
        title_lbl = ctk.CTkLabel(dialog, text=f"Modifier {service}", font=ctk.CTkFont(size=24, weight="bold"))
        title_lbl.pack(pady=(20, 15))
        ctk.CTkLabel(dialog, text="Service :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        service_entry = ctk.CTkEntry(dialog, width=450, height=35)
        service_entry.insert(0, service)
        service_entry.configure(state="disabled")
        service_entry.pack(pady=(0, 10), padx=40)
        ctk.CTkLabel(dialog, text="Utilisateur / Email :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        username_entry = ctk.CTkEntry(dialog, width=450, height=35)
        username_entry.insert(0, data.get("user", ""))
        username_entry.pack(pady=(0, 10), padx=40)
        ctk.CTkLabel(dialog, text="Mot de passe :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        password_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        password_frame.pack(pady=(0, 5), padx=40)
        password_entry = ctk.CTkEntry(password_frame, show="*", width=320, height=35)
        password_entry.insert(0, data.get("pass", ""))
        password_entry.pack(side="left", padx=(0, 10))
        def generate_and_fill():
            pwd = SafeCodeManager.generate_password()
            password_entry.delete(0, "end")
            password_entry.insert(0, pwd)
            update_strength(pwd)
        gen_btn = ctk.CTkButton(password_frame, text="Generer", width=120, height=35, command=generate_and_fill)
        gen_btn.pack(side="left")
        strength_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        strength_frame.pack(pady=(0, 10), padx=40, fill="x")
        strength_label = ctk.CTkLabel(strength_frame, text="Force : ", font=ctk.CTkFont(size=12))
        strength_label.pack(side="left")
        strength_bar = ctk.CTkProgressBar(strength_frame, width=300, height=8)
        strength_bar.pack(side="left", padx=10)
        strength_bar.set(0)
        def update_strength(pwd):
            strength, color = SafeCodeManager.check_password_strength(pwd)
            strength_label.configure(text=f"Force : {strength}", text_color=color)
            if strength == "Faible":
                strength_bar.set(0.33)
                strength_bar.configure(progress_color="#FF4444")
            elif strength == "Moyen":
                strength_bar.set(0.66)
                strength_bar.configure(progress_color="#FFA500")
            else:
                strength_bar.set(1.0)
                strength_bar.configure(progress_color="#00CC00")
        password_entry.bind("<KeyRelease>", lambda e: update_strength(password_entry.get()))
        update_strength(password_entry.get())
        ctk.CTkLabel(dialog, text="Categorie :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        category_entry = ctk.CTkEntry(dialog, width=450, height=35)
        category_entry.insert(0, data.get("category", "Autre"))
        category_entry.pack(pady=(0, 10), padx=40)
        ctk.CTkLabel(dialog, text="Notes :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        notes_entry = ctk.CTkTextbox(dialog, width=450, height=70)
        notes_entry.insert("1.0", data.get("notes", ""))
        notes_entry.pack(pady=(0, 15), padx=40)
        def save():
            username = username_entry.get().strip()
            password = password_entry.get()
            category = category_entry.get().strip() or "Autre"
            notes = notes_entry.get("1.0", "end-1c").strip()
            if not username or not password:
                messagebox.showerror("Erreur", "Utilisateur et mot de passe obligatoires")
                return
            self.manager.update_password(service, username, password, category, notes)
            self.refresh_services_list()
            self.check_duplicates()
            dialog.destroy()
            messagebox.showinfo("Succes", f"Mot de passe modifie pour {service}")
        save_btn = ctk.CTkButton(dialog, text="Enregistrer les modifications", width=250, height=45,
                                 font=ctk.CTkFont(size=15, weight="bold"), command=save)
        save_btn.pack(pady=(10, 20))

    def show_password_dialog(self, service):
        data = self.manager.get_password(service)
        if not data: return
        self.manager.update_activity()
        dialog = ctk.CTkToplevel(self)
        dialog.title(f"Details - {service}")
        dialog.geometry("600x500")
        dialog.transient(self)
        dialog.grab_set()
        title_lbl = ctk.CTkLabel(dialog, text=service, font=ctk.CTkFont(size=28, weight="bold"))
        title_lbl.pack(pady=25)
        ctk.CTkLabel(dialog, text="Utilisateur :", font=ctk.CTkFont(size=13), text_color="gray").pack(anchor="w", padx=50)
        username_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        username_frame.pack(pady=(5, 15), padx=50, fill="x")
        username_entry = ctk.CTkEntry(username_frame, width=200, height=35)
        username_entry.insert(0, data["user"])
        username_entry.configure(state="disabled")
        username_entry.pack(side="left", padx=(0, 10), fill="x", expand=True)
        def copy_username():
            self.clipboard_clear()
            self.clipboard_append(data["user"])
            messagebox.showinfo("Copie", "Utilisateur copie !")
        copy_btn = ctk.CTkButton(username_frame, text="Copier", width=100, height=35, command=copy_username)
        copy_btn.pack(side="left")
        ctk.CTkLabel(dialog, text="Mot de passe :", font=ctk.CTkFont(size=13), text_color="gray").pack(anchor="w", padx=50)
        password_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        password_frame.pack(pady=(5, 15), padx=50, fill="x")
        password_entry = ctk.CTkEntry(password_frame, show="*", width=200, height=35)
        password_entry.insert(0, data["pass"])
        password_entry.configure(state="disabled")
        password_entry.pack(side="left", padx=(0, 10), fill="x", expand=True)
        def toggle_password():
            if password_entry.cget("show") == "*":
                password_entry.configure(show="")
                toggle_btn.configure(text="Masquer")
            else:
                password_entry.configure(show="*")
                toggle_btn.configure(text="Afficher")
        toggle_btn = ctk.CTkButton(password_frame, text="Afficher", width=90, height=35, command=toggle_password)
        toggle_btn.pack(side="left", padx=(0, 10))
        def copy_password():
            self.clipboard_clear()
            self.clipboard_append(data["pass"])
            msg = "Mot de passe copie ! Efface dans 30 secondes"
            messagebox.showinfo("Copie", msg)
            self.after(30000, lambda: self.clipboard_clear())
        copy_btn = ctk.CTkButton(password_frame, text="Copier", width=90, height=35, command=copy_password)
        copy_btn.pack(side="left")
        if data.get("notes"):
            ctk.CTkLabel(dialog, text="Notes :", font=ctk.CTkFont(size=13), text_color="gray").pack(anchor="w", padx=50)
            notes_text = ctk.CTkTextbox(dialog, width=500, height=100)
            notes_text.pack(pady=(5, 15), padx=50)
            notes_text.insert("1.0", data["notes"])
            notes_text.configure(state="disabled")
        close_btn = ctk.CTkButton(dialog, text="Fermer", width=200, height=40,
                                  font=ctk.CTkFont(size=14), command=dialog.destroy)
        close_btn.pack(pady=20)

    def show_change_password_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Changer le mot de passe maitre")
        dialog.geometry("500x480")
        dialog.transient(self)
        dialog.grab_set()
        title_lbl = ctk.CTkLabel(dialog, text="Changer le mot de passe maitre",
                                 font=ctk.CTkFont(size=22, weight="bold"))
        title_lbl.pack(pady=25)
        ctk.CTkLabel(dialog, text="Ancien mot de passe :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        old_entry = ctk.CTkEntry(dialog, show="*", width=400, height=35)
        old_entry.pack(pady=(0, 15), padx=40)
        ctk.CTkLabel(dialog, text="Nouveau mot de passe :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        new_entry = ctk.CTkEntry(dialog, show="*", width=400, height=35)
        new_entry.pack(pady=(0, 10), padx=40)
        strength_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        strength_frame.pack(pady=(0, 15), padx=40, fill="x")
        strength_label = ctk.CTkLabel(strength_frame, text="Force : ", font=ctk.CTkFont(size=12))
        strength_label.pack(side="left")
        strength_bar = ctk.CTkProgressBar(strength_frame, width=280, height=8)
        strength_bar.pack(side="left", padx=10)
        strength_bar.set(0)
        def update_strength(pwd):
            strength, color = SafeCodeManager.check_password_strength(pwd)
            strength_label.configure(text=f"Force : {strength}", text_color=color)
            if strength == "Faible":
                strength_bar.set(0.33)
                strength_bar.configure(progress_color="#FF4444")
            elif strength == "Moyen":
                strength_bar.set(0.66)
                strength_bar.configure(progress_color="#FFA500")
            else:
                strength_bar.set(1.0)
                strength_bar.configure(progress_color="#00CC00")
        new_entry.bind("<KeyRelease>", lambda e: update_strength(new_entry.get()))
        ctk.CTkLabel(dialog, text="Confirmer le nouveau :", font=ctk.CTkFont(size=13)).pack(anchor="w", padx=40)
        confirm_entry = ctk.CTkEntry(dialog, show="*", width=400, height=35)
        confirm_entry.pack(pady=(0, 20), padx=40)
        def change():
            old_pwd = old_entry.get()
            new_pwd = new_entry.get()
            confirm_pwd = confirm_entry.get()
            if not old_pwd or not new_pwd or not confirm_pwd:
                messagebox.showerror("Erreur", "Tous les champs sont obligatoires")
                return
            if new_pwd != confirm_pwd:
                messagebox.showerror("Erreur", "Les nouveaux mots de passe ne correspondent pas")
                return
            if new_pwd == old_pwd:
                messagebox.showerror("Erreur", "Le nouveau mot de passe doit etre different de l'ancien")
                return
            success, message = self.manager.change_master_password(old_pwd, new_pwd)
            if success:
                msg = f"{message}\n\nN'oublie pas ton nouveau mot de passe !"
                messagebox.showinfo("Succes", msg)
                dialog.destroy()
            else:
                messagebox.showerror("Erreur", message)
        change_btn = ctk.CTkButton(dialog, text="Changer le mot de passe", width=250, height=45,
                                   font=ctk.CTkFont(size=14, weight="bold"),
                                   fg_color="#FF8C00", hover_color="#CC7000", command=change)
        change_btn.pack(pady=10)
        cancel_btn = ctk.CTkButton(dialog, text="Annuler", width=150, height=35, command=dialog.destroy)
        cancel_btn.pack(pady=5)

    def show_settings_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Parametres")
        dialog.geometry("450x400")
        dialog.transient(self)
        dialog.grab_set()
        title_lbl = ctk.CTkLabel(dialog, text="Parametres de securite", font=ctk.CTkFont(size=22, weight="bold"))
        title_lbl.pack(pady=25)
        info_lbl = ctk.CTkLabel(dialog, text="Verrouillage automatique apres inactivite :", font=ctk.CTkFont(size=14))
        info_lbl.pack(pady=(10, 20))
        options = [
            ("1 minute", 60),
            ("5 minutes (Defaut)", 300),
            ("15 minutes", 900),
            ("30 minutes", 1800),
            ("Jamais (Desactive)", 0)
        ]
        current_timeout = self.settings.get("lock_timeout", 300)
        selected_var = ctk.StringVar(value=str(current_timeout))
        for text, value in options:
            ctk.CTkRadioButton(dialog, text=text, variable=selected_var, value=str(value),
                              font=ctk.CTkFont(size=14), width=300).pack(pady=8)
        def save_settings():
            new_timeout = int(selected_var.get())
            self.settings["lock_timeout"] = new_timeout
            save_settings(self.settings)
            if new_timeout == 0:
                msg = "Verrouillage automatique desactive !"
            else:
                minutes = new_timeout // 60
                msg = f"Verrouillage automatique regle sur {minutes} minute(s)."
            messagebox.showinfo("Succes", msg)
            dialog.destroy()
        save_btn = ctk.CTkButton(dialog, text="Enregistrer", width=200, height=40,
                                 font=ctk.CTkFont(size=14, weight="bold"), command=save_settings)
        save_btn.pack(pady=30)

    def show_generator_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Generateur")
        dialog.geometry("550x500")
        dialog.transient(self)
        dialog.grab_set()
        title_lbl = ctk.CTkLabel(dialog, text="Generateur de mot de passe", font=ctk.CTkFont(size=24, weight="bold"))
        title_lbl.pack(pady=25)
        length_label = ctk.CTkLabel(dialog, text="Longueur : 20", font=ctk.CTkFont(size=14))
        length_label.pack(pady=(10, 5))
        def update_length_label(value):
            length_label.configure(text=f"Longueur : {int(value)}")
        length_slider = ctk.CTkSlider(dialog, from_=8, to=50, number_of_steps=42,
                                      command=update_length_label, height=20)
        length_slider.set(20)
        length_slider.pack(pady=(0, 25), padx=50, fill="x")
        options_frame = ctk.CTkFrame(dialog, corner_radius=10)
        options_frame.pack(pady=10, padx=50, fill="x")
        use_upper = ctk.CTkCheckBox(options_frame, text="Majuscules (A-Z)", font=ctk.CTkFont(size=13))
        use_upper.pack(anchor="w", pady=10, padx=20)
        use_upper.select()
        use_lower = ctk.CTkCheckBox(options_frame, text="Minuscules (a-z)", font=ctk.CTkFont(size=13))
        use_lower.pack(anchor="w", pady=10, padx=20)
        use_lower.select()
        use_digits = ctk.CTkCheckBox(options_frame, text="Chiffres (0-9)", font=ctk.CTkFont(size=13))
        use_digits.pack(anchor="w", pady=10, padx=20)
        use_digits.select()
        use_symbols = ctk.CTkCheckBox(options_frame, text="Symboles (!@#$...)", font=ctk.CTkFont(size=13))
        use_symbols.pack(anchor="w", pady=10, padx=20)
        use_symbols.select()
        result_entry = ctk.CTkEntry(dialog, width=450, height=40, font=ctk.CTkFont(size=16, family="monospace"))
        result_entry.pack(pady=25)
        def generate():
            password = SafeCodeManager.generate_password(
                length=int(length_slider.get()),
                use_uppercase=use_upper.get(),
                use_lowercase=use_lower.get(),
                use_digits=use_digits.get(),
                use_symbols=use_symbols.get()
            )
            result_entry.delete(0, "end")
            result_entry.insert(0, password)
        gen_btn = ctk.CTkButton(dialog, text="Generer", width=250, height=45,
                                font=ctk.CTkFont(size=15, weight="bold"), command=generate)
        gen_btn.pack(pady=5)
        def copy_result():
            pwd = result_entry.get()
            if pwd:
                self.clipboard_clear()
                self.clipboard_append(pwd)
                messagebox.showinfo("Copie", "Mot de passe copie !")
        copy_btn = ctk.CTkButton(dialog, text="Copier", width=250, height=40,
                                 font=ctk.CTkFont(size=14), command=copy_result)
        copy_btn.pack(pady=5)
        close_btn = ctk.CTkButton(dialog, text="Fermer", width=150, height=35, command=dialog.destroy)
        close_btn.pack(pady=10)

    def delete_service(self, service):
        if messagebox.askyesno("Confirmation", f"Supprimer {service} ?"):
            self.manager.delete_password(service)
            self.refresh_services_list()
            self.check_duplicates()
            messagebox.showinfo("Succes", f"{service} supprime")

    def lock_vault(self, ask_confirmation=True):
        if ask_confirmation:
            if not messagebox.askyesno("Confirmation", "Verrouiller le coffre ?"):
                return
        self.manager.key = None
        self.manager.vault_data = None
        self.show_login_screen()


if __name__ == "__main__":
    app = SafeCodeApp()
    app.mainloop()
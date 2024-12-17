import os
import base64
import hashlib
import json
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKC
from Crypto import Random


class PasswordManagerModel:
    def __init__(self, file='dict_pwd.txt', key_file='key_store.txt'):
        self.file = file  # Datei zur Speicherung der Passwörter
        self.key_file = key_file  # Datei zur Speicherung des Schlüssels
        self.default_key = "password"  # Standardschlüssel
        self.default_key_hash = self.hash_key(self.default_key)  # Hash des Standardschlüssel
        self.ensure_key_file() # Sicherstellen, dass die Schlüsseldatei existiert
        self.ensure_rsa_keys() # Sicherstellen, dass RSA-Schlüssel existieren

    def ensure_key_file(self):
        """
        Sicherstellen, dass die Schlüsseldatei existiert. Falls nicht vorhanden, fragt das Programm den Benutzer,
        ob der Schlüssel neu generiert werden soll und setzt diesen auf den Standardschlüssel zurück.
        Alte Daten werden gelöscht.
        """
        if not os.path.exists(self.key_file):
            response = messagebox.askyesno(
                "Key file missing",
                "Key file not found!\nA new key will be generated and set to the default value 'password'\nAll saved data will be deleted.\n\nDo you want to continue？"
            )
            if response:  # Benutzer stimmt zu
                with open(self.key_file, 'w') as f:
                    f.write(self.default_key_hash)  # Schlüssel auf Standardwert "password" setzen
                open(self.file, 'w').close()  # Daten werden gelöscht
                messagebox.showinfo(
                    "Key reset",
                    "The key has been reset to 'password'。\nPlease change the key immediately!\nAll saved data has been deleted."
                )
            else:
                messagebox.showerror("Key reset", "The key has been reset to 'password'.\nPlease change the key immediately!\nAll saved data has been deleted.")
                exit(0)

    def ensure_rsa_keys(self):
        """
         Sicherstellen, dass RSA-Schlüssel existieren. Falls nicht vorhanden, fragt das Programm den Benutzer,
        ob neue RSA-Schlüssel generiert werden sollen. Dabei werden gespeicherte Daten gelöscht.
        """
        if not os.path.exists("client_private.pem") or not os.path.exists("client_public.pem"):
            response = messagebox.askyesno(
                "RSA key missing",
                "RSA key files were not found！\nCreating new RSA keys will delete all stored data\n\nDo you want to continue？"
            )
            if response:  # Benutzer stimmt zu
                self.create_rsa_key()
                open(self.file, 'w').close()  # Daten werden gelöscht
                messagebox.showinfo("RSA keys generated", "New RSA keys have been created. All data has been deleted")
            else:
                messagebox.showerror("Action aborted", "The program cannot continue. Please restore the RSA key files!")
                exit(0)

    def create_rsa_key(self):
        """Generiert ein neues RSA-Schlüsselpaar"""
        try:
            random_gen = Random.new().read
            rsa = RSA.generate(2048, random_gen)
            with open("client_private.pem", "wb") as f:
                f.write(rsa.exportKey())
            with open("client_public.pem", "wb") as f:
                f.write(rsa.publickey().exportKey())
        except Exception as e:
            messagebox.showerror("Action aborted", f"Unable to generate RSA key: {str(e)}")
            exit(0)

    def hash_key(self, key):
        """Erstellt einen SHA-256-Hash aus dem Schlüssel."""
        return hashlib.sha256(key.encode('utf-8')).hexdigest()

    def verify_key(self, secret):
        """Überprüft, ob der eingegebene Schlüssel korrekt ist."""
        entered_hash = self.hash_key(secret)
        with open(self.key_file, 'r') as f:
            saved_hash = f.read().strip()
        return entered_hash == saved_hash

    def is_default_key(self):
        """Überprüft, ob der aktuelle Schlüssel dem Standardschlüssel entspricht."""
        with open(self.key_file, 'r') as f:
            saved_hash = f.read().strip()
        return saved_hash == self.default_key_hash

    def update_key(self, new_key):
        """Aktualisiert den Benutzer-Schlüssel."""
        new_key_hash = self.hash_key(new_key)
        with open(self.key_file, 'w') as f:
            f.write(new_key_hash)

    def encrypt(self, plaintext):
        """Verschlüsselt die Daten mit dem RSA-öffentlichen Schlüssel."""
        try:
            public_key = RSA.import_key(open("client_public.pem").read())
            cipher_rsa = Cipher_PKC.new(public_key)
            encrypted_data = cipher_rsa.encrypt(plaintext.encode("utf-8"))
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            raise RuntimeError(f"Encryption failed: {str(e)}")

    def decrypt(self, encrypted_data):
        """Entschlüsselt die Daten mit dem RSA-privaten Schlüssel."""
        try:
            base64_data = base64.b64decode(encrypted_data.encode("utf-8"))
            private_key = RSA.import_key(open("client_private.pem").read())
            cipher_rsa = Cipher_PKC.new(private_key)
            decrypted_data = cipher_rsa.decrypt(base64_data, None)
            return decrypted_data.decode()
        except Exception as e:
            raise RuntimeError(f"Decryption failed: {str(e)}")

    def read_passwords(self):
        """Liest die gespeicherten Passwörter und entschlüsselt sie."""
        passwords = []
        try:
            with open(self.file, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        passwords.append(json.loads(self.decrypt(line.strip())))
                    except Exception:
                        continue  # Ungültige Zeilen werden ignoriert
        except FileNotFoundError:
            return []
        return passwords

    def write_password(self, data):
        """Verschlüsselt und speichert ein neues Passwort."""
        with open(self.file, 'a', encoding='utf-8') as f:
            f.write(self.encrypt(json.dumps(data)) + '\n')

    def delete_password(self, data):
        """Löscht einen bestimmten Passwort-Eintrag."""
        passwords = self.read_passwords()
        with open(self.file, 'w', encoding='utf-8') as f:
            for password in passwords:
                if password != data:
                    f.write(self.encrypt(json.dumps(password)) + '\n')

    def clear_all_passwords(self):
        """Löscht alle gespeicherten Passwörter."""
        open(self.file, 'w').close()

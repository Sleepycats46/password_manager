import tkinter as tk
from tkinter import messagebox
from model import PasswordManagerModel
from view import PasswordManagerView, AuthenticationView


class PasswordManagerController:
    def __init__(self, root):
        self.root = root
        self.root.withdraw()
        self.model = PasswordManagerModel()

        # Open the login window
        auth_window = tk.Toplevel(root)
        AuthenticationView(auth_window, self.verify_secret)
        root.wait_window(auth_window)

    def verify_secret(self, secret):
        if self.model.verify_key(secret):
            if self.model.is_default_key():
                messagebox.showwarning("Warning", "You are using the default key. Please update your key!")
            self.view = PasswordManagerView(self.root, self)
            self.root.deiconify()
            return True
        else:
            return False

    def add_password_logic(self, platform, password):
        if platform and password:
            self.model.write_password({"Platform": platform, "Password": password})
            messagebox.showinfo("Success", "Password added successfully！")
            self.view.refresh_password_list()
        else:
            messagebox.showerror("Error", "Platform and password cannot be empty！")

    def update_password_logic(self, old_platform, new_platform, new_password):
        passwords = self.model.read_passwords()
        for record in passwords:
            if record["Platform"] == old_platform:
                self.model.update_password(record, {"Platform": new_platform, "Password": new_password})
                messagebox.showinfo("Success", "Password updated successfully!")
                self.view.refresh_password_list()
                return
        messagebox.showerror("Error", "No matching platform found！")

    def delete_password_logic(self, platform):
        """Delete a selected password entry based on the platform name"""
        passwords = self.model.read_passwords()
        for record in passwords:
            if record["Platform"] == platform:
                self.model.delete_password(record)
                messagebox.showinfo("Success", f"Password for platform '{platform}' deleted successfully！")
                return
        messagebox.showerror("Error", "No matching platform found！")

    def delete_all_passwords_logic(self):
        if messagebox.askyesno("Confirmation", "Are you sure you want to delete all password? This action cannot be undone!"):
            self.model.clear_all_passwords()
            messagebox.showinfo("Success", "All password have been cleared！")
            self.view.refresh_password_list()

    def search_passwords_logic(self, query):
        passwords = self.model.read_passwords()
        return [p for p in passwords if query.lower() in p["Platform"].lower()] if query else passwords

    def show_update_key_window(self):
        window = tk.Toplevel(self.root)
        window.title("Update Key")
        window.geometry("400x200")

        tk.Label(window, text="Old Key:").pack(pady=5)
        old_key_entry = tk.Entry(window, show="*")
        old_key_entry.pack(pady=5)

        tk.Label(window, text="New Key:").pack(pady=5)
        new_key_entry = tk.Entry(window, show="*")
        new_key_entry.pack(pady=5)

        def save_new_key():
            old_key = old_key_entry.get()
            new_key = new_key_entry.get()
            if self.model.verify_key(old_key):
                if new_key:
                    self.model.update_key(new_key)
                    messagebox.showinfo("Success", "Key update successfully！")
                    window.destroy()
                else:
                    messagebox.showerror("Error", "New key cannot be empty！")
            else:
                messagebox.showerror("Error", "Old key is incorrect！")

        tk.Button(window, text="Save", command=save_new_key).pack(pady=10)

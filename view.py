import tkinter as tk
from tkinter import ttk, messagebox


class AuthenticationView:
    def __init__(self, root, verify_callback):
        """Login Verification View"""
        self.root = root
        self.root.title("Log in to Password Manager")
        self.root.geometry("400x200")
        self.verify_callback = verify_callback

        tk.Label(root, text="Enter the key to log in", font=("Arial", 13)).pack(pady=20)
        self.secret_entry = ttk.Entry(root, show="*", font=("Arial", 12))
        self.secret_entry.pack(pady=10, padx=20, fill=tk.X)
        ttk.Button(root, text="Login", command=self.verify_secret).pack(pady=20)

    def verify_secret(self):
        secret = self.secret_entry.get()
        if self.verify_callback(secret):
            self.root.destroy()
        else:
            messagebox.showerror("Error", "Key verification failed. Pleas try again!")


class PasswordManagerView:
    def __init__(self, root, controller):
        self.root = root
        self.controller = controller
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        self.setup_ui()

    def setup_ui(self):
        """Set up the main interface layout"""
        # Left-side function panel
        self.left_frame = ttk.Frame(self.root, width=150)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        ttk.Label(self.left_frame, text="Features", font=("Arial", 14)).pack(pady=10)
        ttk.Button(self.left_frame, text="My Password Book", command=self.show_password_book).pack(fill=tk.X, pady=5)
        ttk.Button(self.left_frame, text="Update Key", command=self.controller.show_update_key_window).pack(fill=tk.X, pady=5)

        # Right-side content area
        self.right_frame = ttk.Frame(self.root)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.show_password_book()

    def show_password_book(self):
        """Display the password book interface."""
        self._clear_right_frame()

        # Search bar
        search_frame = ttk.Frame(self.right_frame)
        search_frame.pack(fill=tk.X, pady=5)
        ttk.Label(search_frame, text="Keyword:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(search_frame, text="Search", command=self.refresh_password_list).pack(side=tk.LEFT, padx=5)

        # Monitor key release event to auto-refresh on empty input
        self.search_entry.bind("<KeyRelease>", lambda event: self.refresh_password_list())

        # Button area
        button_frame = ttk.Frame(self.right_frame)
        button_frame.pack(fill=tk.X, pady=10)
        ttk.Button(button_frame, text="Add New Password", command=lambda: self.show_add_password_window("Add New Password")).pack(
            side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Delete All Passwords", command=self.controller.delete_all_passwords_logic).pack(
            side=tk.LEFT, padx=10)
        self.update_button = ttk.Button(button_frame, text="Update Password", state=tk.DISABLED,
                                        command=self.show_update_password_window)
        self.update_button.pack(side=tk.LEFT, padx=10)
        self.delete_button = ttk.Button(button_frame, text="Delete", state=tk.DISABLED,
                                        command=self.delete_selected_password)
        self.delete_button.pack(side=tk.LEFT, padx=10)

        # Password list display
        self.tree = ttk.Treeview(self.right_frame, columns=("Platform", "Password"), show="headings")
        self.tree.heading("Platform", text="Platform")
        self.tree.heading("Password", text="Password")
        self.tree.column("Platform", anchor="center")
        self.tree.column("Password", anchor="center")
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Bind selection and right-click events
        self.tree.bind("<<TreeviewSelect>>", self.on_item_selected)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Bind left-click on empty space to deselect
        self.tree.bind("<Button-1>", self.on_left_click_blank)

        self.refresh_password_list()

    def on_left_click_blank(self, event):
        """Deselect items when clicking on empty space"""
        region = self.tree.identify_region(event.x, event.y)
        if region == "nothing":
            self.tree.selection_remove(self.tree.selection())
            self.update_button.config(state=tk.DISABLED)
            self.delete_button.config(state=tk.DISABLED)

    def on_item_selected(self, event):
        """Activate update and delete buttons when an item is selected."""
        selected_item = self.tree.selection()
        if selected_item:
            self.update_button.config(state=tk.NORMAL)
            self.delete_button.config(state=tk.NORMAL)
        else:
            self.update_button.config(state=tk.DISABLED)
            self.delete_button.config(state=tk.DISABLED)

    def delete_selected_password(self):
        """Delete the selected password"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a record to delete！")
            return

        platform = self.tree.item(selected_item, "values")[0]
        if messagebox.askyesno("Confirmation", f"Are you sure you want to delete the password for platform？"):
            self.controller.delete_password_logic(platform)
            self.refresh_password_list()

    def show_add_password_window(self, title):
        """Display the add password window."""
        self._show_password_window(title, self.controller.add_password_logic)

    def show_update_password_window(self):
        """Display the update password window"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "Please select a record to update！")
            return

        old_platform = self.tree.item(selected_item, "values")[0]
        self._show_password_window("Update Password",
                                   lambda platform, password: self.controller.update_password_logic(old_platform,
                                                                                                    platform, password))

    def show_context_menu(self, event):
        """Display the right-click menu"""
        selected_item = self.tree.selection()
        if selected_item:
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="Edit", command=self.show_update_password_window)
            menu.add_command(label="Delete", command=lambda: self.delete_selected_password())
            menu.post(event.x_root, event.y_root)

    def _show_password_window(self, title, save_callback):
        """Display the password window (for adding/updating passwords)"""
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("400x250")
        window.minsize(400, 250)

        tk.Label(window, text="Platform:").pack(pady=10)
        platform_entry = tk.Entry(window)
        platform_entry.pack(pady=5)

        tk.Label(window, text="Password:").pack(pady=10)
        password_entry = tk.Entry(window, show="*")
        password_entry.pack(pady=5)

        save_button = ttk.Button(window, text="Save",
                                 command=lambda: self._save_password(platform_entry, password_entry, save_callback,
                                                                     window))
        save_button.pack(pady=20)

    def _save_password(self, platform_entry, password_entry, save_callback, window):
        """Save the password"""
        platform = platform_entry.get()
        password = password_entry.get()
        if platform and password:
            save_callback(platform, password)
            window.destroy()
        else:
            messagebox.showerror("Error", "Platform and password cannot be empty!")

    def refresh_password_list(self):
        """Refresh the password list"""
        for i in self.tree.get_children():
            self.tree.delete(i)
        query = self.search_entry.get().strip()
        if query:
            passwords = self.controller.search_passwords_logic(query)
        else:
            passwords = self.controller.search_passwords_logic("")
        for record in passwords:
            self.tree.insert("", "end", values=(record["Platform"], record["Password"]))

    def _clear_right_frame(self):
        for widget in self.right_frame.winfo_children():
            widget.destroy()

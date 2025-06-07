import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64

# Glyph substitution table
glyph_map = {
    **dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", list("дБⲊϕ𞤒ҐⰔߒYუꓘՀကЛΣφՋণডႥဂλЖ㐅ψℵ"))),
    **dict(zip("abcdefghijklmnopqrstuvwxyz", list("𐒀𑀩€𐑓ᛂ𐰯𐒍ᚺπ𐌾𐑗ᛚ𐎈∆ᜂ§𐓀𐰺𐊊𐰕𐎒ᚡ𐑇√𐒎𐤌"))),
    **dict(zip("0123456789", list("0123456789"))),
    "+": "+",
    "/": "*"
}
reverse_glyph_map = {v: k for k, v in glyph_map.items()}

def encrypt_message(message, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    combined = salt + cipher.nonce + tag + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt_message(b64_string, password):
    try:
        combined = base64.b64decode(b64_string)
        salt, nonce, tag, ciphertext = combined[:16], combined[16:32], combined[32:48], combined[48:]
        key = PBKDF2(password, salt, dkLen=32, count=100_000)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode('utf-8')
    except Exception:
        return None

def to_glyph_base64(b64_string):
    return ''.join(glyph_map.get(c, '?') for c in b64_string)

def from_glyph_base64(glyph_string):
    return ''.join(reverse_glyph_map.get(c, '?') for c in glyph_string)

class GlyphCryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Boogaloo Flatline Encryption Software")
        self.configure(bg="#000000")
        self.geometry("1000x600")

        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', background='#000000', foreground='#39FF14', fieldbackground='#111111')
        style.configure('TLabel', background='#000000', foreground='#39FF14')
        style.configure('TButton', background='#222222', foreground='#39FF14')
        style.map('TButton', background=[('active', '#333333')])
        style.configure('TEntry', fieldbackground='#111111', foreground='#39FF14')
        style.configure('TRadiobutton', background='#000000', foreground='#39FF14')
        style.configure('TCheckbutton', background='#000000', foreground='#39FF14')

        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)

        self.mode = tk.StringVar(value="encrypt")

        # Mode buttons at top
        encrypt_rb = ttk.Radiobutton(container, text="Encrypt", variable=self.mode, value="encrypt", command=self.toggle_mode)
        decrypt_rb = ttk.Radiobutton(container, text="Decrypt", variable=self.mode, value="decrypt", command=self.toggle_mode)
        encrypt_rb.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        decrypt_rb.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        # Labels
        self.input_label = ttk.Label(container, text="Enter message to encrypt:")
        self.input_label.grid(row=1, column=0, sticky="w", padx=10)

        self.output_label = ttk.Label(container, text="Encrypted output:")
        self.output_label.grid(row=1, column=1, sticky="w", padx=10)

        # Text boxes side by side
        self.input_text = scrolledtext.ScrolledText(container, height=20, width=55, wrap="word",
                                                    bg="#111111", fg="#39FF14",
                                                    insertbackground="#39FF14", font=("Consolas", 12))
        self.input_text.grid(row=2, column=0, padx=10, pady=5)

        self.output_text = scrolledtext.ScrolledText(container, height=20, width=55, wrap="word",
                                                     bg="#111111", fg="#39FF14",
                                                     font=("Consolas", 12))
        self.output_text.grid(row=2, column=1, padx=10, pady=5)

        # BLOCK user editing but allow selection & copying on output_text
        def block_edit(event):
            return "break"
        self.output_text.bind("<Key>", block_edit)
        self.output_text.bind("<Control-v>", block_edit)
        self.output_text.bind("<Button-3>", block_edit)

        # Passphrase label and entry
        ttk.Label(container, text="Passphrase:").grid(row=3, column=0, sticky="w", padx=10, pady=5)
        self.pass_entry = ttk.Entry(container, show="*", font=("Consolas", 12))
        self.pass_entry.grid(row=3, column=1, sticky="ew", padx=10, pady=5)

        # Action button
        self.action_button = ttk.Button(container, text="Encrypt", command=self.process)
        self.action_button.grid(row=4, column=0, columnspan=2, pady=15)

        container.columnconfigure(1, weight=1)

        self.toggle_mode()

    def toggle_mode(self):
        mode = self.mode.get()
        if mode == "encrypt":
            self.input_label.config(text="Enter message to encrypt:")
            self.output_label.config(text="Encrypted output:")
            self.action_button.config(text="Encrypt")
        else:
            self.input_label.config(text="Enter glyph message to decrypt:")
            self.output_label.config(text="Decrypted output:")
            self.action_button.config(text="Decrypt")

        self.input_text.config(state="normal")
        self.output_text.config(state="normal")
        self.output_text.delete("1.0", tk.END)

    def process(self):
        password = self.pass_entry.get()
        if not password:
            messagebox.showwarning("Passphrase Missing", "Please enter a passphrase.")
            return

        if self.mode.get() == "encrypt":
            plaintext = self.input_text.get("1.0", tk.END).strip()
            if not plaintext:
                messagebox.showwarning("Input Missing", "Please enter a message to encrypt.")
                return
            encrypted_b64 = encrypt_message(plaintext, password)
            glyph_message = to_glyph_base64(encrypted_b64)
            self.output_text.config(state="normal")
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, glyph_message)
            self.output_text.config(state="normal") # Keep normal for selection & copy
        else:
            glyph_message = self.input_text.get("1.0", tk.END).strip()
            if not glyph_message:
                messagebox.showwarning("Input Missing", "Please enter a glyph message to decrypt.")
                return
            b64_message = from_glyph_base64(glyph_message)
            decrypted = decrypt_message(b64_message, password)
            self.output_text.config(state="normal")
            self.output_text.delete("1.0", tk.END)
            if decrypted is not None:
                self.output_text.insert(tk.END, decrypted)
            else:
                self.output_text.insert(tk.END, "[Decryption failed or invalid input]")
            self.output_text.config(state="normal") # Keep normal for selection & copy

if __name__ == "__main__":
    app = GlyphCryptoApp()
    app.mainloop()
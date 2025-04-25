import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
import base64

# --- 3DES FUNCTIONS ---

def generate_3des_key():
    """Generate a valid 3DES key"""
    while True:
        key = get_random_bytes(24)
        try:
            DES3.new(key, DES3.MODE_ECB)
            return key
        except ValueError:
            continue

def pad_message(message):
    """Pad message to be multiple of 8 bytes (DES block size)"""
    padding_length = 8 - (len(message) % 8)
    padding = bytes([padding_length]) * padding_length
    return message + padding

def unpad_message(padded_message):
    """Remove PKCS7 padding"""
    padding_length = padded_message[-1]
    return padded_message[:-padding_length]

def encrypt_3des(message, key):
    """Encrypt a message using 3DES"""
    cipher = DES3.new(key, DES3.MODE_ECB)
    message_bytes = message.encode('utf-8')
    padded_message = pad_message(message_bytes)
    encrypted_message = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_3des(encrypted_message, key):
    """Decrypt a 3DES encrypted message"""
    cipher = DES3.new(key, DES3.MODE_ECB)
    encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted_message = unpad_message(decrypted_padded)
    return decrypted_message.decode('utf-8')

# --- GUI APP CLASS ---

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("3DES Encryption/Decryption")
        self.root.geometry("600x400")
        self.root.configure(padx=20, pady=20)

        self.key = generate_3des_key()
        self.create_widgets()

    def create_widgets(self):
        style = ttk.Style()
        style.configure('TButton', padding=5)
        style.configure('TLabel', padding=5)
        style.configure('TEntry', padding=5)

        ttk.Label(self.root, text="Enter Message:").grid(row=0, column=0, sticky='w')
        self.message_entry = ttk.Entry(self.root, width=50)
        self.message_entry.grid(row=1, column=0, columnspan=2, sticky='ew', pady=5)

        button_frame = ttk.Frame(self.root)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="Encrypt", command=self.encrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt).pack(side='left', padx=5)

        result_frame = ttk.Frame(self.root)
        result_frame.grid(row=3, column=0, columnspan=2, sticky='ew')

        ttk.Label(result_frame, text="Result:").pack(side='left')
        ttk.Button(result_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(side='right')

        self.result_text = tk.Text(self.root, height=10, width=50, wrap=tk.WORD)
        self.result_text.grid(row=4, column=0, columnspan=2, sticky='ew', pady=5)

        self.root.grid_columnconfigure(0, weight=1)

    def copy_to_clipboard(self):
        result = self.result_text.get(1.0, tk.END).strip()
        if result:
            message = result.split('\n', 1)[1] if '\n' in result else result
            self.root.clipboard_clear()
            self.root.clipboard_append(message)
            messagebox.showinfo("Success", "Text copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No text to copy!")

    def encrypt(self):
        try:
            message = self.message_entry.get()
            if not message:
                messagebox.showwarning("Warning", "Please enter a message to encrypt")
                return
            encrypted = encrypt_3des(message, self.key)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Encrypted message:\n{encrypted}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt(self):
        try:
            message = self.message_entry.get()
            if not message:
                messagebox.showwarning("Warning", "Please enter a message to decrypt")
                return
            decrypted = decrypt_3des(message, self.key)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Decrypted message:\n{decrypted}")
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed. Please ensure you entered a valid encrypted message.")

def main():
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

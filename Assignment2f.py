import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def generate_aes_key(key_size=256):
    key_bytes = key_size // 8
    return get_random_bytes(key_bytes)

def encrypt_aes(message, key, mode=AES.MODE_CBC):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, mode, iv)
    message_bytes = message.encode('utf-8')
    padded_message = pad(message_bytes, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    result = base64.b64encode(iv + encrypted_message).decode('utf-8')
    return result

def decrypt_aes(encrypted_message, key, mode=AES.MODE_CBC):
    try:
        encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
        iv = encrypted_bytes[:AES.block_size]
        ciphertext = encrypted_bytes[AES.block_size:]
        cipher = AES.new(key, mode, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_message = unpad(decrypted_padded, AES.block_size)
        return decrypted_message.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Encryption/Decryption")
        self.root.geometry("700x500")
        self.root.configure(padx=20, pady=20)
        self.key_size = tk.IntVar(value=256)
        self.key = generate_aes_key(self.key_size.get())
        self.create_widgets()

    def create_widgets(self):
        style = ttk.Style()
        style.configure('TButton', padding=5)
        style.configure('TLabel', padding=5)
        style.configure('TEntry', padding=5)
        style.configure('TRadiobutton', padding=3)

        key_frame = ttk.LabelFrame(self.root, text="AES Key Size")
        key_frame.grid(row=0, column=0, columnspan=2, sticky='ew', pady=5)
        
        ttk.Radiobutton(key_frame, text="128-bit (10 rounds)", variable=self.key_size, 
                        value=128, command=self.regenerate_key).grid(row=0, column=0, padx=10, sticky='w')
        ttk.Radiobutton(key_frame, text="192-bit (12 rounds)", variable=self.key_size, 
                        value=192, command=self.regenerate_key).grid(row=0, column=1, padx=10, sticky='w')
        ttk.Radiobutton(key_frame, text="256-bit (14 rounds)", variable=self.key_size, 
                        value=256, command=self.regenerate_key).grid(row=0, column=2, padx=10, sticky='w')
        
        ttk.Button(key_frame, text="Generate New Key", command=self.regenerate_key).grid(
            row=0, column=3, padx=10, sticky='e')

        ttk.Label(self.root, text="Enter Message:").grid(row=1, column=0, sticky='w', pady=(10, 0))
        self.message_entry = ttk.Entry(self.root, width=70)
        self.message_entry.grid(row=2, column=0, columnspan=2, sticky='ew', pady=5)

        button_frame = ttk.Frame(self.root)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="Encrypt", command=self.encrypt).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt).pack(side='left', padx=5)

        result_frame = ttk.Frame(self.root)
        result_frame.grid(row=4, column=0, columnspan=2, sticky='ew')

        ttk.Label(result_frame, text="Result:").pack(side='left')
        ttk.Button(result_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(side='right')

        self.result_text = tk.Text(self.root, height=12, width=70, wrap=tk.WORD)
        self.result_text.grid(row=5, column=0, columnspan=2, sticky='ew', pady=5)
        
        info_frame = ttk.LabelFrame(self.root, text="About AES Encryption")
        info_frame.grid(row=6, column=0, columnspan=2, sticky='ew', pady=10)
        
        info_text = """
AES (Advanced Encryption Standard) is a symmetric block cipher that processes data in 128-bit blocks.
Key features:
• Supports key sizes of 128, 192, and 256 bits
• Uses substitution-permutation network with multiple rounds
• Faster and more secure than DES/3DES
• Resistant to all known attacks when implemented correctly
• Uses CBC mode with random IV for added security
        """
        ttk.Label(info_frame, text=info_text, justify='left').grid(padx=10, pady=5)

        self.root.grid_columnconfigure(0, weight=1)

    def regenerate_key(self):
        self.key = generate_aes_key(self.key_size.get())
        messagebox.showinfo("Key Generated", f"New {self.key_size.get()}-bit AES key generated successfully")

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
            encrypted = encrypt_aes(message, self.key)
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
            decrypted = decrypt_aes(message, self.key)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Decrypted message:\n{decrypted}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def main():
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
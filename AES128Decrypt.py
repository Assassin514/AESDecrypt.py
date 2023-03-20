from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import messagebox

BLOCK_SIZE = 16


def validate_input(input_text):
    """
    Validate that input is a string of 16 bytes (128 bits)
    """
    if len(input_text) != 16:
        return False
    for c in input_text:
        if not 0 <= ord(c) <= 255:
            return False
    return True


def encrypt_message(message):
    """
    Encrypt a message with AES-128 bit encryption
    """
    if not validate_input(key_entry.get()):
        messagebox.showerror("Error", "Key must be a 16-byte string")
        return
    if not validate_input(message_entry.get()):
        messagebox.showerror("Error", "Message must be a 16-byte string")
        return
    key = key_entry.get().encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode('utf-8'), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_message)
    ciphertext_hex = ciphertext.hex()
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, ciphertext_hex)


def decrypt_message(ciphertext_hex):
    """
    Decrypt a message with AES-128 bit encryption
    """
    if not validate_input(key_entry.get()):
        messagebox.showerror("Error", "Key must be a 16-byte string")
        return
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError:
        messagebox.showerror("Error", "Ciphertext must be a hex-encoded string")
        return
    key = key_entry.get().encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = cipher.decrypt(ciphertext)
    padded_message = decrypted_message.decode('utf-8')
unpadded_message = unpad(padded_message, BLOCK_SIZE)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, message)


# Create GUI
root = tk.Tk()
root.title("AES Encryption/Decryption")
root.geometry("500x300")

key_label = tk.Label(root, text="Enter 16-byte Key:")
key_label.pack()

key_entry = tk.Entry(root, width=50)
key_entry.pack()

message_label = tk.Label(root, text="Enter 16-byte Message:")
message_label.pack()

message_entry = tk.Entry(root, width=50)
message_entry.pack()

encrypt_button = tk.Button(root, text="Encrypt", command=lambda: encrypt_message(message_entry.get()))
encrypt_button.pack()

decrypt_label = tk.Label(root, text="Enter Ciphertext (hex-encoded):")
decrypt_label.pack()

decrypt_entry = tk.Entry(root, width=50)
decrypt_entry.pack()

decrypt_button = tk.Button(root, text="Decrypt", command=lambda: decrypt_message(decrypt_entry.get()))
decrypt_button.pack()

result_label = tk.Label(root, text="Result:")
result_label.pack()

result_text = tk.Text(root, height=5)
result_text.pack()

root.mainloop()

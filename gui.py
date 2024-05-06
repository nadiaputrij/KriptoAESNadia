from pathlib import Path
from tkinter import Tk, Canvas, Text, Button, PhotoImage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hmac, hashes
import os

OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH /Path(r"D:\SEMESTER 4\Keamanan Informasi\build\assets\frame0")
def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / path

def encrypt_text(plaintext, key):
    backend = default_backend()
    iv = os.urandom(16)  # Generate a random IV (for CBC mode)
    cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv), backend=backend)  # Use the first 128 bits of the key
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext

def decrypt_text(ciphertext, key):
    backend = default_backend()
    iv = ciphertext[:16]  # Extract IV from ciphertext
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key[:16]), modes.CBC(iv), backend=backend)  # Use the first 128 bits of the key
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext.decode()

def generate_key():
    if not Path("key.txt").exists():
        key = os.urandom(16)  # 128-bit key
        with open("key.txt", "wb") as f:
            f.write(key)
    else:
        with open("key.txt", "rb") as f:
            key = f.read()
    return key

def authenticate_data(data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def encrypt_and_authenticate():
    plaintext = entry_1.get("1.0", "end-1c")
    key = generate_key()
    try:
        ciphertext = encrypt_text(plaintext, key)
        auth_tag = authenticate_data(ciphertext, key)
        encrypted_data_with_tag = ciphertext + auth_tag
        entry_2.delete("1.0", "end")
        entry_2.insert("1.0", encrypted_data_with_tag.hex())
    except Exception as e:
        entry_2.delete("1.0", "end")
        entry_2.insert("1.0", f"Error: {str(e)}")

def decrypt_and_verify():
    encrypted_data_with_tag_hex = entry_1.get("1.0", "end-1c")
    encrypted_data_with_tag = bytes.fromhex(encrypted_data_with_tag_hex)
    key = generate_key()
    ciphertext = encrypted_data_with_tag[:-32]  # Exclude authentication tag
    auth_tag = encrypted_data_with_tag[-32:]  # Extract authentication tag
    computed_auth_tag = authenticate_data(ciphertext, key)
    if computed_auth_tag == auth_tag:
        try:
            plaintext = decrypt_text(ciphertext, key)
            entry_2.delete("1.0", "end")
            entry_2.insert("1.0", plaintext)
        except Exception as e:
            entry_2.delete("1.0", "end")
            entry_2.insert("1.0", f"Error: {str(e)}")
    else:
        entry_2.delete("1.0", "end")
        entry_2.insert("1.0", "Authentication failed")
window = Tk()
window.geometry("800x500")
window.configure(bg="#DAB3DB")

canvas = Canvas(
    window,
    bg="#DAB3DB",
    height=500,
    width=800,
    bd=0,
    highlightthickness=0,
    relief="ridge"
)
canvas.place(x=0, y=0)

image_image_1 = PhotoImage(file=relative_to_assets("image_1.png"))
image_1 = canvas.create_image(58.0, 56.0, image=image_image_1)

image_image_2 = PhotoImage(file=relative_to_assets("image_2.png"))
image_2 = canvas.create_image(293.0, 48.0, image=image_image_2)

image_image_3 = PhotoImage(file=relative_to_assets("image_3.png"))
image_3 = canvas.create_image(294.0, 242.0, image=image_image_3)

entry_image_1 = PhotoImage(file=relative_to_assets("entry_1.png"))
entry_bg_1 = canvas.create_image(436.5, 139.5, image=entry_image_1)
entry_1 = Text(bd=0, bg="#FFFFFF", fg="#000716", highlightthickness=0)
entry_1.place(x=188.0, y=100.0, width=497.0, height=77.0)

entry_image_2 = PhotoImage(file=relative_to_assets("entry_2.png"))
entry_bg_2 = canvas.create_image(436.5, 334.5, image=entry_image_2)
entry_2 = Text(bd=0, bg="#FFFFFF", fg="#000716", highlightthickness=0)
entry_2.place(x=188.0, y=295.0, width=497.0, height=77.0)

button_image_1 = PhotoImage(file=relative_to_assets("button_1.png"))
button_1 = Button(image=button_image_1, borderwidth=0, highlightthickness=0, command=encrypt_and_authenticate, relief="flat")
button_1.place(x=105.0, y=414.0, width=165.0, height=49.0)

button_image_2 = PhotoImage(file=relative_to_assets("button_2.png"))
button_2 = Button(image=button_image_2, borderwidth=0, highlightthickness=0, command=decrypt_and_verify, relief="flat")
button_2.place(x=602.0, y=409.0, width=165.0, height=49.0)

window.resizable(False, False)
window.mainloop()

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_keys(password, key_size, progress_bar): #RSA key generation
    try:
        progress_bar.start(10)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,                       #key length passed to the function
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,     #convert private ket to PEM format
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            if password else serialization.NoEncryption()
        )

        with open('private_key.pem', 'wb') as f:
            f.write(private_pem)                     #save private key

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,     ##convert public ket to PEM format
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open('public_key.pem', 'wb') as f:
            f.write(public_pem)                     #save public key

        progress_bar.stop()
        messagebox.showinfo("Keys Generation", "Keys Generated Successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))      #if there is any error, show message
        progress_bar.stop()

def encrypt_file(file_path, public_key_path, progress_bar):
    try:
        progress_bar.start(10)
        with open(public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend()) #open public key
        
        #generate random keys
        key = os.urandom(32) #256 bit key for AES, if you want 128 bit AES key - change value "32" to "16"
        iv = os.urandom(16)  #128 bit initialization vector (dont change)
        
        #Encrytpion AES key by public key RSA and OAEP
        encrypted_key = public_key.encrypt(
            key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #Create AES encryption object in CBC using the generated key and iv
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        #open original file, 
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        #plaintext is original, unencrypted data
        #The encryption process is to converting plaintext to unknown(encrypted) text using encryption algorithm and encryption key.
        padding_length = 16 - len(plaintext) % 16 #padding length math, how many bytes of padding should be added (a multiple of 16 bytes)
        padding_plaintext = plaintext + bytes([padding_length] * padding_length) #add padding to plaintext
        ciphertext  = encryptor.update(padding_plaintext) + encryptor.finalize() #encryption with added padding
        #create and save .encrypted file
        encrypted_file_path = file_path + '.encrypted'
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted_key + iv + ciphertext )

        progress_bar.stop()
        messagebox.showinfo("Encryption", f"File Encrypted Successfully!\nSaved at {encrypted_file_path}") #show message and path to save encrypted file
    except Exception as e:
        messagebox.showerror("Error", str(e))
        progress_bar.stop()


def decrypt_file(file_path, private_key_path, password, progress_bar):
    try:
        progress_bar.start(10)
        #open and read private key
        with open(private_key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None,
                backend=default_backend()
            )

        #open and read encrypted file, read AES key
        with open(file_path, 'rb') as f:
            encrypted_key = f.read(private_key.key_size // 8)
            iv = f.read(16)
            ciphertext  = f.read()

        #Encrypted by AES using private key
        key = private_key.decrypt(
            encrypted_key,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #create AES object with CBC and using AES key and iv
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        #encrypted data, remove padding from file
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]

        #save encrypted data
        decrypted_file_path = file_path.replace('.encrypted', '')
        with open(decrypted_file_path, 'wb') as f:
            f.write(plaintext)

        #show message with location
        progress_bar.stop()
        messagebox.showinfo("Decryption", f"File Decrypted Successfully!\nSaved at {decrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        progress_bar.stop()

#run task in different thread to prevent blocking program
def run_threaded(task, *args):
    threading.Thread(target=task, args=args).start()

def main_app():
    root = tk.Tk()
    root.title('kar_encryptor 1.0')
    root.geometry('300x200')
    root.iconbitmap('icon.ico')

    progress_bar = ttk.Progressbar(root, mode='indeterminate')
    progress_bar.pack(fill='x')

    key_size_var = tk.IntVar(value=2048)

    def generate_keys_wrapper():
        password = simpledialog.askstring("Password", "Enter password for key(leave blank if none):", show='*')
        key_size = key_size_var.get()
        run_threaded(generate_keys, password, key_size, progress_bar)

    def encrypt_file_wrapper():
        file_path = filedialog.askopenfilename(title="Select a file to encrypt")
        public_key_path = filedialog.askopenfilename(title="Select the public key")
        run_threaded(encrypt_file, file_path, public_key_path, progress_bar)

    def decrypt_file_wrapper():
        file_path = filedialog.askopenfilename(title="Select a file to decrypt")
        private_key_path = filedialog.askopenfilename(title="Select the private key")
        password = simpledialog.askstring("Password", "Enter your private key password (if any):", show='*')
        run_threaded(decrypt_file, file_path, private_key_path, password, progress_bar)

    #buttons
    ttk.Button(root, text="Generate Public and Private keys", command=generate_keys_wrapper).pack(fill='x')
    ttk.Button(root, text="Encrypt File", command=encrypt_file_wrapper).pack(fill='x')
    ttk.Button(root, text="Decrypt File", command=decrypt_file_wrapper).pack(fill='x')

    #key length to choose
    ttk.Radiobutton(root, text="2048 bits", variable=key_size_var, value=2048).pack(fill='x')
    ttk.Radiobutton(root, text="4096 bits", variable=key_size_var, value=4096).pack(fill='x')
    ttk.Radiobutton(root, text="8192 bits", variable=key_size_var, value=8192).pack(fill='x')
    ttk.Radiobutton(root, text="16384 bits", variable=key_size_var, value=16384).pack(fill='x')

    root.mainloop()

if __name__ == "__main__":
    main_app()


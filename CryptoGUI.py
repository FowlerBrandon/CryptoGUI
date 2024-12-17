import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, ChaCha20, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
import CipherSuite as cs
import os.path

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Crypto GUI")
        
    
        button_width = 20
        button_height = 3
        button_color = "orange"

        header_color = "gray"
        bg_color = "gray"

        self.geometry("1500x700")
        self.configure(bg=bg_color)

        # Create frames for each screen
        self.frame1 = tk.Frame(self, bg=bg_color)
        self.frame2 = tk.Frame(self, bg=bg_color)
        self.frame3 = tk.Frame(self, bg=bg_color)


        # Create widgets for each frame
        self.encryption_method = tk.StringVar(self.frame1)
        self.encryption_method.set("AES-256-CBC")
        encryption_choices = ["AES-256-CBC" , "CHACHA20", "RSA-Public", "RSA-Private"]
        encrypt_dropdown = tk.OptionMenu(self.frame1, self.encryption_method, *encryption_choices)
        self.encryption_file = None
        self.output_file = None
        self.output_file_name = tk.StringVar(self.frame1, value="No file selected")
        self.encrypt_file_name = tk.StringVar(self.frame1, value="No file selected")
        tk.Label(self.frame1, text="Encryption", bg=header_color).pack()
        tk.Button(self.frame1, text="Decryption", command=self.show_frame2, width=button_width, height=button_height, bg=button_color).pack(side="left", padx=20)
        tk.Button(self.frame1, text="Signature", command=self.show_frame3, width=button_width, height=button_height, bg=button_color).pack(side="right", padx=20)
        tk.Button(self.frame1, text="Generate RSA Keypair", command=self.generate_rsa_pair, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Label(self.frame1, text="Passphrase for RSA Private Key", bg=bg_color).pack(side="top", pady=10)
        self.passphrase = tk.Entry(self.frame1).pack(side="top", pady=20)
        tk.Button(self.frame1, text="Initiate Encryption", command=self.encrypt, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Button(self.frame1,text="Select File to Encrypt", command= self.set_encryption_file, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Button(self.frame1, text="Select Output File", command= self.set_output_file, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Label(self.frame1, textvariable=self.encrypt_file_name , bg=bg_color).pack(side="top", pady=20)
        tk.Label(self.frame1, textvariable=self.output_file_name , bg=bg_color).pack(side="top", pady=20)
       
        encrypt_dropdown.pack(side="bottom", pady=20)



        decryption_method = tk.StringVar(self.frame1)
        decryption_method.set("AES-256-CBC")
        decryption_choices = ["AES-256-CBC" , "CHACHA20", "RSA-Public", "RSA-Private"]
        decrypt_dropdown = tk.OptionMenu(self.frame2, decryption_method, *decryption_choices)
        
        tk.Label(self.frame2, text="Decryption", bg=header_color).pack()
        tk.Button(self.frame2, text="Signature", command=self.show_frame3, width=button_width, height=button_height, bg=button_color).pack(side="left", padx=20)
        tk.Button(self.frame2, text="Encryption", command=self.show_frame1, width=button_width, height=button_height, bg=button_color).pack(side="right", padx=20)
        tk.Label(self.frame2, text="Passphrase for RSA Private Key", bg=bg_color).pack(side="top", pady=10)
        self.passphrase = tk.Entry(self.frame2).pack(side="top", pady=20)
        tk.Button(self.frame2, text="Initiate Decryption", command=self.decrypt, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Button(self.frame2,text="Select File to Decrypt", command= self.set_decryption_file, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Button(self.frame2, text="Select Output File", command= self.set_output_file, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Label(self.frame2, textvariable=self.encrypt_file_name , bg=bg_color).pack(side="top", pady=20)
        tk.Label(self.frame2, textvariable=self.output_file_name , bg=bg_color).pack(side="top", pady=20)
        
        decrypt_dropdown.pack(side="bottom", pady=20)



        tk.Label(self.frame3, text="Signature", bg=header_color).pack()
        tk.Button(self.frame3, text="Encryption", command=self.show_frame1, width=button_width, height=button_height, bg=button_color).pack(side="left", padx=20)
        tk.Button(self.frame3, text="Decryption", command=self.show_frame2, width=button_width, height=button_height, bg=button_color).pack(side="right", padx=20)
        tk.Button(self.frame3, text="Sign File", command=self.sign_file, width=button_width, height=button_height, bg=button_color).pack(side="right", padx=20)
        tk.Button(self.frame3, text="Verify Signature", command=self.verify_signature, width=button_width, height=button_height, bg=button_color).pack(side="right", padx=20)
        # Show the initial frame
        self.show_frame1()
    
    def set_encryption_file(self):
        encryption_file = filedialog.askopenfile()
        if encryption_file:
            self.encryption_file = encryption_file
            self.encrypt_file_name.set(f"File to encrypt: {encryption_file.name}")
    
    def set_decryption_file(self):
        encryption_file = filedialog.askopenfile()
        if encryption_file:
            self.encryption_file = encryption_file
            self.encrypt_file_name.set(f"File to decrypt: {encryption_file.name}")
            

    def set_output_file(self):
        output_file = filedialog.asksaveasfile()
        if output_file:
            self.output_file = output_file
            self.output_file_name.set(f"File to output: {output_file.name}")
    
    def generate_rsa_pair(self):

        rsa_keysize = 2048
        pubkey_name = "RSAPublic.pem"
        privkey_name = "RSAPrivate.pem"

        privkey = RSA.generate(rsa_keysize)
        privkey_fin = privkey.export_key(passphrase=self.passphrase, pkcs=8,
                                        protection='PBKDF2WithHMAC-SHA512AndAES256'
                                                '-CBC',
                                        prot_params={'iteration_count':131072})
        pubkey = privkey.public_key()
        pubkey_fin = pubkey.export_key()
       
        open("Keys/" + privkey_name, "wb").write(privkey_fin)
        open("Keys/" + pubkey_name, "wb").write(pubkey_fin)
        pass

    def sign_file(self):
        pass

    def verify_signature(self):
        pass

    def encrypt(self):
       
        if self.encryption_method.get() == "RSA-Public":
            publicPath = "Keys/RSAPublic.pem"
            if publicPath:
                key_open = open(publicPath).read()
                key = RSA.import_key(key_open)
                out_file = cs.encrypt_rsa(self.encryption_file.name, key)
                open(self.output_file.name, "w").write(str(out_file))
            else:
                messagebox.showerror("Error", "Issue with encryption")
        elif self.encryption_method.get() == "RSA-Private":
            privatePath = "Keys/RSAPrivate.pem"
            if privatePath:
                key_open = open(privatePath).read()
                key = RSA.import_key(key_open, passphrase=self.passphrase)
                out_file = cs.encrypt_rsa(self.encryption_file.name, key)
                open(self.output_file.name, "w").write(str(out_file))
            else:
                messagebox.showerror("Error", "Issue with encryption")
            
        elif self.encryption_method.get() == "AES-256-CBC":
            key=cs.gen_key()
            key_name = "AES_key.pem"
            out_file, iv = cs.encrypt_cbc(self.encryption_file.name, key)
            open("Keys/" + key_name, "w").write(b64encode(key).decode("utf-8"))
            open(self.output_file.name + "_iv", "w").write(iv)
            open(self.output_file.name, "w").write(str(out_file))

        elif self.encryption_method.get() == "CHACHA20":
            key=cs.gen_key()
            key_name = "ChaCha20_key.pem"
            out_file, nonce = cs.encrypt_chacha(self.encryption_file.name, key)
            open("Keys/" + key_name, "w").write(b64encode(key).decode("utf-8"))
            open(self.output_file.name + "_nonce", "w").write(nonce)
            open(self.output_file.name, "w").write(str(out_file))
       

    def decrypt(self):
        if self.encryption_method.get() == "RSA-Public":
            publicPath = "Keys/RSAPublic.pem"
            if publicPath:
                key_open = open(publicPath).read()
                key = RSA.import_key(key_open)
                # attempting to privately decrypt and RSA file flags an error in line 176 for some reason
                # my best guess is that it is trying to use public decryption for some reason i cannot find
                out_file = cs.decrypt_rsa(self.encryption_file.name, key)
                open(self.output_file.name, "w").write(str(out_file))
            else:
                messagebox.showerror("Error", "Issue with encryption")

        elif self.encryption_method.get() == "RSA-Private":
            privatePath = "Keys/RSAPrivate.pem"
            if privatePath:
                key_open = open(privatePath).read()
                key = RSA.import_key(key_open, passphrase=self.passphrase)
                out_file = cs.decrypt_rsa(self.encryption_file.name, key)
                open(self.output_file.name, "w").write(str(out_file))
            else:
                messagebox.showerror("Error", "Issue with encryption")

        elif self.encryption_method.get() == "AES-256-CBC":
            key_path = "Keys/AES_key.pem"
            key = open(key_path).read()
            iv = open(self.encryption_file.name + "_iv").read()
            out_file = cs.decrypt_cbc(self.encryption_file.name, key, iv)
            open(self.output_file.name, "w").write(str(out_file))

        elif self.encryption_method.get() == "CHACHA20":
            key_path = "Keys/ChaCha20_key.pem"
            key = open(key_path).read()
            nonce = open(self.encryption_file.name + "_nonce").read()
            out_file = cs.decrypt_chacha(self.encryption_file.name, key, nonce)
            open(self.output_file.name, "w").write(str(out_file))

    def show_frame1(self):
        self.frame2.pack_forget()
        self.frame3.pack_forget()
        self.frame1.pack()

    def show_frame2(self):
        self.frame1.pack_forget()
        self.frame3.pack_forget()
        self.frame2.pack()

    def show_frame3(self):
        self.frame2.pack_forget()
        self.frame1.pack_forget()
        self.frame3.pack()

if __name__ == "__main__":
    app = App()
    app.mainloop()
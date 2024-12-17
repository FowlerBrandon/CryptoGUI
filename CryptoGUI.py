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
        self.encryption_passphrase = tk.Entry(self.frame1)
        self.encryption_passphrase.pack(side="top", pady=20)
        tk.Button(self.frame1, text="Initiate Encryption", command=self.encrypt, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Button(self.frame1,text="Select File to Encrypt", command= self.set_encryption_file, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Button(self.frame1, text="Select Output File", command= self.set_output_file, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Label(self.frame1, textvariable=self.encrypt_file_name , bg=bg_color).pack(side="top", pady=20)
        tk.Label(self.frame1, textvariable=self.output_file_name , bg=bg_color).pack(side="top", pady=20)
       
        encrypt_dropdown.pack(side="bottom", pady=20)



        self.decryption_method = tk.StringVar(self.frame2)
        self.decryption_method.set("AES-256-CBC")
        decryption_choices = ["AES-256-CBC" , "CHACHA20", "RSA-Public", "RSA-Private"]
        decrypt_dropdown = tk.OptionMenu(self.frame2, self.decryption_method, *decryption_choices)
        self.decryption_file = None
        self.decryption_output = None
        self.decryption_file_name = tk.StringVar(self.frame2, value="No file selected")
        self.decryption_output_name = tk.StringVar(self.frame2, value="No file selected")
        
        tk.Label(self.frame2, text="Decryption", bg=header_color).pack()
        tk.Button(self.frame2, text="Signature", command=self.show_frame3, width=button_width, height=button_height, bg=button_color).pack(side="left", padx=20)
        tk.Button(self.frame2, text="Encryption", command=self.show_frame1, width=button_width, height=button_height, bg=button_color).pack(side="right", padx=20)
        tk.Label(self.frame2, text="Passphrase for RSA Private Key", bg=bg_color).pack(side="top", pady=10)
        self.decryption_passphrase = tk.Entry(self.frame2)
        self.decryption_passphrase.pack(side="top", pady=20)
        tk.Button(self.frame2, text="Initiate Decryption", command=self.decrypt, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Button(self.frame2,text="Select File to Decrypt", command= self.set_decryption_file, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Button(self.frame2, text="Select Output File", command= self.set_decryption_output, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Label(self.frame2, textvariable=self.decryption_file_name , bg=bg_color).pack(side="top", pady=20)
        tk.Label(self.frame2, textvariable=self.decryption_output_name , bg=bg_color).pack(side="top", pady=20)
        
        decrypt_dropdown.pack(side="bottom", pady=20)


        self.content_file = None
        self.sign_output = None
        self.verify_file = None
        self.verify_pubkey = None
        self.file_signature = None

        self.content_file_label = tk.StringVar(self.frame3, value="No file selected")
        self.sign_output_label = tk.StringVar(self.frame3, value="No file selected")
        self.verify_file_label = tk.StringVar(self.frame3, value="No file selected")
        self.verify_pubkey_label = tk.StringVar(self.frame3, value="No file selected")
        self.file_signature_label = tk.StringVar(self.frame3, value="No file selected")
        

        
        tk.Label(self.frame3, text="Signature", bg=header_color).pack()
        tk.Button(self.frame3, text="Encryption", command=self.show_frame1, width=button_width, height=button_height, bg=button_color).pack(side="left", padx=20)
        tk.Button(self.frame3, text="Decryption", command=self.show_frame2, width=button_width, height=button_height, bg=button_color).pack(side="right", padx=20)
        tk.Button(self.frame3, text="Sign File", command=self.sign_file, width=button_width, height=button_height, bg=button_color).pack(side="left", padx=20)
        tk.Button(self.frame3, text="Verify Signature", command=self.verify_signature, width=button_width, height=button_height, bg=button_color).pack(side="right", padx=20)
        tk.Label(self.frame3, text="Sign File", bg=bg_color).pack(side="top", pady=20)
        tk.Button(self.frame3, text="Select File to Sign", command=self.set_content_file, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Label(self.frame3, textvariable=self.content_file_label, bg=bg_color).pack(side="top", pady=20)
        tk.Label(self.frame3, text="Password for Private Key: ", bg=bg_color).pack(side="top", pady=20)
        self.signature_passphrase = tk.Entry(self.frame3)
        self.signature_passphrase.pack(side="top", pady=20)
        tk.Button(self.frame3, text="Select Output File", command=self.set_sign_output, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Label(self.frame3, textvariable=self.sign_output_label, bg=bg_color).pack(side="top", pady=20)
        tk.Label(self.frame3, text="Verify Signature", bg=bg_color).pack(side="top", pady=20)
        tk.Button(self.frame3, text="Select File to Verify", command=self.set_verify_file, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Label(self.frame3, textvariable=self.verify_file_label, bg=bg_color).pack(side="top", pady=20)
        tk.Button(self.frame3, text="Select Public Key", command=self.set_verify_pubkey, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Label(self.frame3, textvariable=self.verify_pubkey_label, bg=bg_color).pack(side="top", pady=20)
        tk.Button(self.frame3, text="Select File Signature", command=self.set_file_signature, width=button_width, height=button_height, bg=button_color).pack(side="top", pady=20)
        tk.Label(self.frame3, textvariable=self.file_signature_label, bg=bg_color).pack(side="top", pady=20)
        
        # Show the initial frame
        self.show_frame1()
    

    def set_content_file(self):
        content_file = filedialog.askopenfile()
        if content_file:
            self.content_file = content_file
            self.content_file_label.set(f"File to Sign: {content_file.name}")
        
    
    def set_sign_output(self):
        sign_output = filedialog.asksaveasfile()
        if sign_output:
            self.sign_output = sign_output
            self.sign_output_label.set(f"Output for File Signature: {sign_output.name}")

    def set_verify_file(self):
        verify_file = filedialog.askopenfile()
        if verify_file:
            self.verify_file = verify_file
            self.verify_file_label.set(f"File to Verify: {verify_file.name}")
    
    def set_verify_pubkey(self):
        verify_pubkey = filedialog.askopenfile()
        if verify_pubkey:
            self.verify_pubkey = verify_pubkey
            self.verify_pubkey_label.set(f"Public Key: {verify_pubkey}")

    def set_file_signature(self):
        file_signature = filedialog.askopenfile()
        if file_signature:
            self.file_signature = file_signature
            self.file_signature_label.set(f"File Signature: {file_signature}")


    def set_decryption_file(self):
        decryption_file = filedialog.askopenfile()
        if decryption_file:
            self.decryption_file = decryption_file
            self.decryption_file_name.set(f"File to decrypt: {decryption_file.name}")

    def set_decryption_output(self):
        decryption_output = filedialog.asksaveasfile()
        if decryption_output:
            self.decryption_output = decryption_output
            self.decryption_output_name.set(f"File to output: {decryption_output.name}")

    def set_encryption_file(self):
        encryption_file = filedialog.askopenfile()
        if encryption_file:
            self.encryption_file = encryption_file
            self.encrypt_file_name.set(f"File to encrypt: {encryption_file.name}")
            
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
        privkey_fin = privkey.export_key(passphrase=self.encryption_passphrase.get(), pkcs=8,
                                        protection='PBKDF2WithHMAC-SHA512AndAES256'
                                                '-CBC',
                                        prot_params={'iteration_count':131072})
        print(self.encryption_passphrase.get())
        pubkey = privkey.public_key()
        pubkey_fin = pubkey.export_key()
       
        open("Keys/" + privkey_name, "wb").write(privkey_fin)
        open("Keys/" + pubkey_name, "wb").write(pubkey_fin)
        pass

    def sign_file(self):
        privatePath = "Keys/RSAPrivate.pem"
        key_open = open(privatePath).read()
        key = RSA.import_key(key_open, self.signature_passphrase.get())
        signed_file = cs.sign_rsa(self.content_file.name, key)
        open(self.sign_output.name, "wb").write(signed_file)
        

    def verify_signature(self):
        key_open = open(self.verify_pubkey.name).read()
        key = RSA.import_key(key_open)
        valid = cs.verify_rsa(self.verify_file.name, key, self.file_signature.name)

        if valid:
            messagebox.showinfo("Verification Status", "Valid")
        else:
            messagebox.showinfo("Verification Status", "Invalid")

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
                key = RSA.import_key(key_open, passphrase=self.encryption_passphrase.get())
                print(self.encryption_passphrase.get())
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
        if self.decryption_method.get() == "RSA-Public":
            publicPath = "Keys/RSAPublic.pem"
            if publicPath:
                key_open = open(publicPath).read()
                key = RSA.import_key(key_open)
                # attempting to privately decrypt and RSA file flags an error in line 176 for some reason
                # my best guess is that it is trying to use public decryption for some reason i cannot find
                out_file = cs.decrypt_rsa(self.decryption_file.name, key)
                open(self.decryption_output.name, "w").write(str(out_file))
            else:
                messagebox.showerror("Error", "Issue with encryption")

        elif self.decryption_method.get() == "RSA-Private":
            privatePath = "Keys/RSAPrivate.pem"
            if privatePath:
                key_open = open(privatePath).read()
                print(self.decryption_passphrase.get())
                key = RSA.import_key(key_open, passphrase=self.decryption_passphrase.get())
                out_file = cs.decrypt_rsa(self.decryption_file.name, key)
                print(out_file)
                open(self.decryption_output.name, "w").write(str(out_file))
            else:
                messagebox.showerror("Error", "Issue with encryption")

        elif self.decryption_method.get() == "AES-256-CBC":
            key_path = "Keys/AES_key.pem"
            key = open(key_path).read()
            iv = open(self.decryption_file.name + "_iv").read()
            out_file = cs.decrypt_cbc(self.decryption_file.name, key, iv)
            open(self.decryption_output.name, "w").write(str(out_file))

        elif self.encryption_method.get() == "CHACHA20":
            key_path = "Keys/ChaCha20_key.pem"
            key = open(key_path).read()
            nonce = open(self.decryption_file.name + "_nonce").read()
            out_file = cs.decrypt_chacha(self.decryption_file.name, key, nonce)
            open(self.decryption_output.name, "w").write(str(out_file))

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
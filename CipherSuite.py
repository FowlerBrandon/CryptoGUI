import Crypto.Signature.pss
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS



def gen_key():
        key = get_random_bytes(32)
        return key


def gen_cha_key():
        key = get_random_bytes(32)
        return key


def encrypt_ecb(in_file, key):
        cipher = AES.new(key, AES.MODE_ECB)
        plain_file = open(in_file).read().encode()
        ciphertext = b64encode(cipher.encrypt(pad(plain_file,
                                                AES.block_size))).decode('utf-8')
        return ciphertext


def encrypt_cbc(in_file, key):
        cipher = AES.new(key, AES.MODE_CBC)
        iv = b64encode(cipher.iv).decode('utf-8')
        plain_file = open(in_file).read().encode()
        ciphertext = b64encode(cipher.encrypt(pad(plain_file,
                                                AES.block_size))).decode('utf-8')
        return ciphertext, iv


def encrypt_ctr(in_file, key):
        cipher = AES.new(key, AES.MODE_CTR)
        nonce = b64encode(cipher.nonce).decode('utf-8')
        plain_file = open(in_file).read().encode()
        ciphertext = b64encode(cipher.encrypt(plain_file)).decode('utf-8')
        return ciphertext, nonce


def encrypt_cfb(in_file, key):
        cipher = AES.new(key, AES.MODE_CFB)
        iv = b64encode(cipher.iv).decode('utf-8')
        plain_file = open(in_file).read().encode()
        ciphertext = b64encode(cipher.encrypt(plain_file)).decode('utf-8')
        return ciphertext, iv


def encrypt_ofb(in_file, key):
        cipher = AES.new(key, AES.MODE_OFB)
        iv = b64encode(cipher.iv).decode('utf-8')
        plain_file = open(in_file).read().encode()
        ciphertext = b64encode(cipher.encrypt(plain_file)).decode('utf-8')
        return ciphertext, iv


def encrypt_chacha(in_file, key):
        cipher = ChaCha20.new(key=key)
        nonce = b64encode(cipher.nonce).decode('utf-8')
        plain_file = open(in_file).read().encode()
        ciphertext = b64encode(cipher.encrypt(plain_file)).decode('utf-8')
        return ciphertext, nonce

def encrypt_rsa(in_file, key):
        cipher = PKCS1_OAEP.new(key=key)
        plain_file = open(in_file).read().encode()
        ciphertext = b64encode(cipher.encrypt(plain_file)).decode('utf-8')
        return ciphertext


def decrypt_ecb(in_file, key):
        cipher = AES.new(b64decode(key.encode('utf-8')), AES.MODE_ECB, )
        plain_file = open(in_file).read()
        plaintext = unpad(cipher.decrypt(b64decode(plain_file.encode('utf-8'))),
                        AES.block_size)
        return plaintext

 
def decrypt_cbc(in_file, key, iv):
        cipher = AES.new(b64decode(key.encode('utf-8')), AES.MODE_CBC,
                        iv=b64decode(iv.encode('utf-8')))
        plain_file = open(in_file).read()
        plaintext = unpad(cipher.decrypt(b64decode(plain_file.encode('utf-8'))),
                        AES.block_size)
        return plaintext


def decrypt_ctr(in_file, key, nonce):
        cipher = AES.new(b64decode(key.encode('utf-8')), AES.MODE_CTR,
                        nonce=b64decode(nonce.encode('utf-8')))
        plain_file = open(in_file).read()
        plaintext = cipher.decrypt(b64decode(plain_file.encode('utf-8')))
        return plaintext


def decrypt_cfb(in_file, key, iv):
        cipher = AES.new(b64decode(key.encode('utf-8')), AES.MODE_CFB,
                        iv=b64decode(iv.encode('utf-8')))
        plain_file = open(in_file).read()
        plaintext = cipher.decrypt(b64decode(plain_file.encode('utf-8')))
        return plaintext


def decrypt_ofb(in_file, key, iv):
        cipher = AES.new(b64decode(key.encode('utf-8')), AES.MODE_OFB,
                        iv=b64decode(iv.encode('utf-8')))
        plain_file = open(in_file).read()
        plaintext = cipher.decrypt(b64decode(plain_file.encode('utf-8')))
        return plaintext


def decrypt_chacha(in_file, key, nonce):
        cipher = ChaCha20.new(key=b64decode(key.encode('utf-8')),
                            nonce=b64decode(nonce.encode('utf-8')))
        plain_file = open(in_file).read()
        plaintext = cipher.decrypt(b64decode(plain_file.encode('utf-8')))
        return plaintext


def decrypt_rsa(in_file, key):
        cipher = PKCS1_OAEP.new(key=key)
        plain_file = open(in_file).read()
        plaintext = cipher.decrypt(b64decode(plain_file.encode('utf-8')))
        return plaintext


def sign_rsa(in_file, key):
        cipher = pkcs1_15.new(key)
        open_file = open(in_file, "rb").read()
        sign_hash = SHA256.new(open_file)
        signed_file = cipher.sign(sign_hash)
        return signed_file

def sign_ecc(in_file, key):
        cipher = DSS.new(key, 'fips-186-3')
        open_file = open(in_file, "rb").read()
        sign_hash = SHA256.new(open_file)
        signed_file = cipher.sign(sign_hash)
        return signed_file


def verify_rsa(in_file, key, signature_file):
        verify = pkcs1_15.new(key)
        open_file = open(in_file, "rb").read()
        verify_hash = SHA256.new(open_file)
        signature = open(signature_file, "rb").read()
        valid = True

        try:
            verify.verify(verify_hash, signature)

        except ValueError:
            valid = False

        return valid


def verify_ecc(in_file, key, signature_file):
        verify = DSS.new(key, 'fips-186-3')
        open_file = open(in_file, "rb").read()
        verify_hash = SHA256.new(open_file)
        signature = open(signature_file, "rb").read()
        valid = True

        try:
            verify.verify(verify_hash, signature)

        except ValueError:
            valid = False

        return valid


def main():
        choice = ""

        while choice.upper() != "Q":
            print("\nEnter G to generate a keypair (RSA or ECC).\nEnter E to "
                "encrypt a "
                "file.\nEnter D to decrypt a file.\nEnter S to sign a "
                "file.\nEnter V to verify a signature.\nEnter Q to quit the "
                "program.")
            choice = input()

            if choice.upper() == "Q":
                print("Closing program.")

            elif choice.upper() == "E":
                file_in = input("Name of the file to encrypt:")
                file_out = input("Name of the output file:")
                cipher = "NA"
                mode = "NA"

                while cipher == "NA":
                    cipher = input("Cipher to use (Choices are AES, Chacha20, "
                                "or RSA):")

                    if cipher.lower() == "aes":
                        key = get_random_bytes(32)
                        while mode == "NA":
                            mode = input("Select AES mode (ECB/CBC/CTR/CFB/OFB):")

                            if mode.upper() == "ECB":
                                enc_file = encrypt_ecb(file_in, key)

                            elif mode.upper() == "CBC":
                                enc_file, iv = encrypt_cbc(file_in, key)
                                open("iv_" + file_out, "w").write(iv)

                            elif mode.upper() == "CTR":
                                enc_file, nonce = encrypt_ctr(file_in, key)
                                open("nonce_" + file_out, "w").write(nonce)

                            elif mode.upper() == "CFB":
                                enc_file, iv = encrypt_cfb(file_in, key)
                                open("iv_" + file_out, "w").write(iv)

                            elif mode.upper() == "OFB":
                                enc_file, iv = encrypt_ofb(file_in, key)
                                open("iv_" + file_out, "w").write(iv)

                            else:
                                mode = "NA"
                                print("Invalid Selection!\n")

                    elif cipher.lower() == "chacha20":
                        key = gen_cha_key()
                        enc_file, nonce = encrypt_chacha(file_in, key)
                        open("nonce_" + file_out, "w").write(nonce)

                    elif cipher.lower() == "rsa":
                        while mode == "NA":
                            mode = input("Public or private encryption:")

                            if mode.lower() == "public":
                                key_file = input("Enter name of key file:")
                                key_open = open(key_file).read()
                                key = RSA.import_key(key_open)
                                enc_file = encrypt_rsa(file_in, key)

                            elif mode.lower() == "private":
                                key_file = input("Enter name of key file:")
                                keypass = input("Enter key passprhase:")
                                key_open = open(key_file).read()
                                key = RSA.import_key(key_open, passphrase=keypass)
                                enc_file = encrypt_rsa(file_in, key)


                            else:
                                mode = "NA"
                                print("Invalid Selection!\n")

                    else:
                        cipher = "NA"
                        print("Invalid Selection!\n")

                open(file_out, "w").write(str(enc_file))
                if cipher.lower() != "rsa":
                    open("key_" + file_out, "w").write(b64encode(key).decode('utf-8'
                                                                            ''))

            elif choice.upper() == "D":
                file_in = input("Name of the file to decrypt:")
                file_out = input("Name of the output file:")
                cipher = "NA"
                mode = "NA"

                while cipher == "NA":
                    cipher = input("Cipher to use (Choices are AES, Chacha20, "
                                "or RSA):")

                    if cipher.lower() == "aes":
                        key_file = input("Name of the key file:")
                        key = open(key_file).read()

                        while mode == "NA":
                            mode = input("Select AES mode (ECB/CBC/CTR/CFB/OFB):")

                            if mode.upper() == "ECB":
                                plain_file = decrypt_ecb(file_in, key)

                            elif mode.upper() == "CBC":
                                iv_file = input("Name of the iv file:")
                                iv_open = open(iv_file).read()
                                plain_file = decrypt_cbc(file_in, key, iv_open)

                            elif mode.upper() == "CTR":
                                nonce_file = input("Name of the nonce file:")
                                nonce_open = open(nonce_file).read()
                                plain_file = decrypt_ctr(file_in, key, nonce_open)

                            elif mode.upper() == "CFB":
                                iv_file = input("Name of the iv file:")
                                iv_open = open(iv_file).read()
                                plain_file = decrypt_cfb(file_in, key, iv_open)

                            elif mode.upper() == "OFB":
                                iv_file = input("Name of the iv file:")
                                iv_open = open(iv_file).read()
                                plain_file = decrypt_ofb(file_in, key, iv_open)

                            else:
                                mode = "NA"
                                print("Invalid Selection!\n")

                    elif cipher.lower() == "chacha20":
                        key_file = input("Name of the key file:")
                        key = open(key_file).read()
                        nonce_file = input("Name of the nonce file:")
                        nonce_open = open(nonce_file).read()
                        plain_file = decrypt_chacha(file_in, key, nonce_open)

                    elif cipher.lower() == "rsa":
                        while mode == "NA":
                            mode = input("Public or private decryption:")

                            if mode.lower() == "public":
                                key_file = input("Enter name of key file:")
                                key_open = open(key_file).read()
                                key = RSA.import_key(key_open)
                                plain_file = decrypt_rsa(file_in, key)

                            elif mode.lower() == "private":
                                key_file = input("Enter name of key file:")
                                keypass = input("Enter key passprhase:")
                                key_open = open(key_file).read()
                                key = RSA.import_key(key_open, passphrase=keypass)
                                plain_file = decrypt_rsa(file_in, key)

                            else:
                                mode = "NA"
                                print("Invalid Selection!\n")

                    else:
                        cipher = "NA"
                        print("Invalid Selection!\n")

                open(file_out, "w").write(str(plain_file))

            elif choice.upper() == "G":
                mode = input("Enter type of signature (RSA or ECC): ")
                privkey_name = input("Enter filename to store the private key: ")
                pubkey_name = input("Enter filename to store the public key: ")
                keypass = input("Enter passphrase to protect the private key:")

                if mode.upper() == "RSA":
                    keysize = int(input("Enter key size: "))

                    privkey = RSA.generate(keysize)
                    privkey_fin = privkey.export_key(passphrase=keypass, pkcs=8,
                                        protection='PBKDF2WithHMAC-SHA512AndAES256'
                                                '-CBC',
                                        prot_params={'iteration_count':131072})
                    pubkey = privkey.public_key()
                    pubkey_fin = pubkey.export_key()

                    open(privkey_name, "wb").write(privkey_fin)
                    open(pubkey_name, "wb").write(pubkey_fin)
                elif mode.upper() == "ECC":
                    privkey = ECC.generate(curve='p256')
                    with open(privkey_name, "wt") as f:
                        data = privkey.export_key(format='PEM', passphrase=keypass,
                                    protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                    prot_params={'iteration_count': 131072})
                        f.write(data)

                    pubkey = privkey.public_key()

                    with open(pubkey_name, "wt") as f:
                        data = pubkey.public_key().export_key(format='PEM')
                        f.write(data)

            elif choice.upper() == "S":
                mode = input("Enter type of signature (RSA or ECC): ")
                file_in = input("Enter filename of the content to sign: ")
                key_file = input("Enter filename of the private key to sign: ")
                keypass = input("Enter passphrase for the private key (if any): ")
                file_out = input("Enter filename to store the signature: ")

                if mode.upper() == "RSA":
                    key_open = open(key_file).read()
                    key = RSA.import_key(key_open, keypass)
                    signed_file = sign_rsa(file_in, key)
                    open(file_out, "wb").write(signed_file)

                elif mode.upper() == "ECC":
                    key_open = open(key_file).read()
                    key = ECC.import_key(key_open, keypass)
                    signed_file = sign_ecc(file_in, key)
                    open(file_out, "wb").write(signed_file)

            elif choice.upper() == "V":
                mode = input("Enter type of signature (RSA or ECC): ")
                file_in = input("Enter filename of the content that was signed: ")
                key_file = input("Enter filename of the public key to verify: ")
                signature = input("Enter filename of the signature: ")

                if mode.upper() == "RSA":
                    key_open = open(key_file).read()
                    key = RSA.import_key(key_open)
                    valid = verify_rsa(file_in, key, signature)

                    if valid:
                        print("Signature verified.")
                    else:
                        print("Signature invalid.")

                elif mode.upper() == "ECC":
                    key_open = open(key_file).read()
                    key = ECC.import_key(key_open)
                    valid = verify_ecc(file_in, key, signature)

                    if valid:
                        print("Signature verified.")
                    else:
                        print("Signature invalid.")

            else:
                print("Invalid response!")


if __name__ == '__main__':
        main()

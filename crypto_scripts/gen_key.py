from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

def gen_keypair(): 
    secret_code = "Unguessable"
    key = RSA.generate(2048)
    encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,
                              protection="scryptAndAES128-CBC")

    file_out = open("rsa_privkey.bin", "wb")
    file_out.write(encrypted_key)
    file_out.close()

    file_out = open("rsa_pubkey.bin", "wb")
    file_out.write(key.publickey().export_key())
    file_out.close()

gen_keypair()
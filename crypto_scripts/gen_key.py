from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import os

# Generate the RSA key for every user

USER_LIST = 'ABC'

'''
Generate an RSA keypair with an exponent of 65537 in PEM format
param: bits The key length in bits, USER_ID
Return private key and public key
'''

def generate_RSA(USER, password):


    new_key = RSA.generate(bits=2048, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey(passphrase=password)

    file_out = open("./SETUP/rsa_privkey_" + USER + ".pem", "wb")
    file_out.write(private_key)
    file_out.close()


    file_out_pub = open("./SETUP/pubkey_list.txt", "ab")
    file_out_pub.write(("user:" + USER + "|pubkey:").encode(encoding='utf_8')+ public_key)
    file_out_pub.close
    return private_key, public_key

if os.stat("pubkey_list.txt").st_size != 0:
    open('pubkey_list.txt', 'w').close()

for USER in USER_LIST:
    password = ''
    while len(password) <= 8:
        print('The password length should be at least 8')
        password = input(USER + ' Type your password: ')
    generate_RSA(USER, password)

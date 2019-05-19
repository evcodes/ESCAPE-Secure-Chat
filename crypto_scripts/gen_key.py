from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import sys
import getopt
import os
import getpass



# Generate the RSA key for every user
USER_LIST = ''

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='l:', longopts=['help','directory:'])
except getopt.GetoptError:
	print('Usage: python gen_key.py -l <user_list>')
	sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python gen_key.py -l <user_list>')
        sys.exit(0)
    elif opt == '-l':
        USER_LIST = arg


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

if os.stat("./SETUP/pubkey_list.txt").st_size != 0:
    print("HELP")
    open('./SETUP/pubkey_list.txt', 'a').close()

for USER in USER_LIST:
    password = ''
    while len(password) <= 8:
        print('The password length should be at least 8')
        password = getpass.getpass('Password for ' + USER + ":" )
        print(password)
    generate_RSA(USER, password)

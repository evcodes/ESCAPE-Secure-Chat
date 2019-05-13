# A Generate the group Key
# Access others' public key
# Generate time stamp
# Sign with participant, key, timestamp
# Establish the network
# Send the message to the receiver

# Receiver
# Decrept
# Verify the signature


import sys, getopt
import time
from base64 import b64encode
from Crypto.Signature import PKCS1_PSS
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from netsim.netinterface import network_interface
from base64 import b64encode
from base64 import b64decode
from os import urandom

pubkey_list_address = 'SETUP/pubkey_list.txt'
priv_key_address ='SETUP/rsa_privkey_A.pem'

NET_PATH = './'
OWN_ADDR = 'A'
INITIATOR_ID = OWN_ADDR
PARTICIPANT_LIST = 'ABC'

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:', longopts=['help','passphrase:'])
except getopt.GetoptError:
	print('Usage: python establish_session_initiate.py -p <passphrase>')
	sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python establish_session_initiate.py -p <passphrase>')
        sys.exit(0)
    elif opt == '-p' or opt == '--pass':
        PASS = arg

# random_bytes = urandom(16)
# token = b64encode(random_bytes).decode('utf-8')
# print(token)
shared_key = urandom(16)

shared_key_str = b64encode(shared_key).decode('utf-8')
print(b64decode(shared_key_str.encode('utf_8')))

# a = str(shared_key, 'utf_8')


pubkey_list_read = open(pubkey_list_address, "r")
pubkey_list_file = pubkey_list_read.read()
pubkey_list_read.close()

privkey_read = open(priv_key_address, "r")
privkey_file = privkey_read.read()
privkey_read.close()


# def save_shared_key(shared_key, pubkey, OWN_ADDR, NET_PATH):
# 	addr_dir = NET_PATH + OWN_ADDR + '/shared_key'
# 	if not os.path.exists(addr_dir):
# 		print('Folder for address ' + addr_dir + ' does not exist. Trying to create it... ', end='')
# 		os.mkdir(addr_dir)
# 	f=open(addr_dir+"/shared_key.txt", "wb")
# 	RSA_cipher = PKCS1_OAEP.new(pubkey)
# 	enc_shared_key = RSA_cipher.encrypt(shared_key)
# 	f.write(enc_shared_key)




try:
    sign_priv_key = RSA.importKey(privkey_file, passphrase=PASS)

    timestamp = int(time.time()*1000000)
    timestamp_str = str(timestamp)
    print(timestamp)

    netif = network_interface(NET_PATH, OWN_ADDR)
    print('Main loop started...')
    ### Use ISO 11770-3/2 instead 3/3
    for PARTICIPANT in PARTICIPANT_LIST:
        pubkey_list = pubkey_list_file.split("user:")
        pubkey_list.remove("")
        checker = 0
        for key in pubkey_list:
            if key[0] == PARTICIPANT:
                checker +=1
                get_key = key.split("pubkey:")
                key_str = get_key[1]
            # elif key[0] == INITIATOR_ID:
            #     get_key = key.split("pubkey:")
            #     key_str = get_key[1]
            #     pubkey = RSA.importKey(key_str)
            #     save_shared_key(shared_key, pubkey, OWN_ADDR, NET_PATH):
        if checker == 0:
            print("No such public key string found!")

        pubkey = RSA.importKey(key_str)
        p_text = (INITIATOR_ID + shared_key_str).encode(encoding='utf_8')
        print(len(p_text))
        # print(shared_key.decode(encoding = 'utf_8'))
        RSA_cipher = PKCS1_OAEP.new(pubkey)
        c_text = RSA_cipher.encrypt(p_text)

        p_signed_text = (PARTICIPANT + timestamp_str).encode(encoding='utf_8') + c_text
        h_signed_text = SHA256.new()
        h_signed_text.update(p_signed_text)

        signer = PKCS1_v1_5.new(sign_priv_key)
        sig = signer.sign(h_signed_text)

        shared_key_message = timestamp_str.encode(encoding='utf_8') + c_text + sig
        print(shared_key_message)
        print(len(shared_key_message))
        # print(len(timestamp_str.enocde(encoding='utf_8')))
        print(len(c_text))
        netif.send_msg(PARTICIPANT, shared_key_message)
        netif.send_msg(PARTICIPANT, shared_key_message)
        print("Establish session initiated")

except ValueError:
    print("Passphrase Wrong!")

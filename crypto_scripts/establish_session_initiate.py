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


NET_PATH = './'
OWN_ADDR = ''
PARTICIPANT_LIST = ''


try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hi:p:l:', longopts=['help','passphrase:'])
except getopt.GetoptError:
	print('Usage: python establish_session_initiate.py -i <own_addr> -p <passphrase> -l <addr_list>')
	sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python establish_session_initiate.py -i <own_address> -p <passphrase> -l <address_list>')
        sys.exit(0)
    elif opt == '-i':
        OWN_ADDR =arg
    elif opt == '-p' or opt == '--pass':
        PASS = arg
    elif opt == '-l':
        PARTICIPANT_LIST = arg
priv_key_address ='SETUP/rsa_privkey_' + OWN_ADDR +'.pem'

INITIATOR_ID = OWN_ADDR

shared_key = urandom(16)
shared_key_str = b64encode(shared_key).decode('utf-8')

pubkey_list_read = open(pubkey_list_address, "r")
pubkey_list_file = pubkey_list_read.read()
pubkey_list_read.close()

privkey_read = open(priv_key_address, "r")
privkey_file = privkey_read.read()
privkey_read.close()

try:
    sign_priv_key = RSA.importKey(privkey_file, passphrase=PASS)

    timestamp = int(time.time()*1000000)
    timestamp_str = str(timestamp)


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

        if checker == 0:
            print("No such public key string found!")

        pubkey = RSA.importKey(key_str)
        p_text = (INITIATOR_ID + shared_key_str).encode(encoding='utf_8')


        RSA_cipher = PKCS1_OAEP.new(pubkey)
        c_text = RSA_cipher.encrypt(p_text)

        p_signed_text = (PARTICIPANT + timestamp_str).encode(encoding='utf_8') + c_text
        h_signed_text = SHA256.new()
        h_signed_text.update(p_signed_text)

        signer = PKCS1_v1_5.new(sign_priv_key)
        sig = signer.sign(h_signed_text)

        shared_key_message = timestamp_str.encode(encoding='utf_8') + c_text + sig

        netif.send_msg(PARTICIPANT, shared_key_message)
        netif.send_msg(PARTICIPANT, shared_key_message)
        print("Establish session initiated")

except ValueError:
    print("Passphrase Wrong!")

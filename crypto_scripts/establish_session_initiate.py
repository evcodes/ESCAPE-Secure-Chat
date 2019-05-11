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

pubkey_list_address = 'SETUP/pubkey_list.txt'
priv_key_address ='SETUP/rsa_privkey_A.pem'

NET_PATH = './'
OWN_ADDR = 'A'
INITIATOR_ID = OWN_ADDR
PARTICIPANT_LIST = 'BC'

shared_key = get_random_bytes(16)
print(shared_key)

pubkey_list_read = open(pubkey_list_address, "r")
pubkey_list_file = pubkey_list_read.read()
pubkey_list_read.close()

privkey_read = open(priv_key_address, "r")
privkey_file = privkey_read.read()
privkey_read.close()

sign_priv_key = RSA.importKey(privkey_file)

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
        # print(key)
        if key[0] == PARTICIPANT:
            checker +=1
            get_key = key.split("pubkey:")
            key_str = get_key[1]
            print(key_str)
    if checker == 0:
        print("No such public key string found!")

    pubkey = RSA.importKey(key_str)
    p_text = (INITIATOR_ID + str(shared_key)).encode(encoding='utf_8')
    print(len(shared_key))
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
    netif.send_msg('B', shared_key_message)
    print("Establish session initiated")
# A Generate the group Key
# Access others' public key
# Generate time stamp
# Sign with participant, key, timestamp
# Establish the network
# Send the message to the receiver

# Receiver
# Decrypt
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

pubkey_list_address = 'SETUP/pubkey_list.txt'
priv_key_address ='SETUP/rsa_privkey_A.pem'

INITIATOR_ID = 'A'
PARTICIPANT_LIST = 'BC'

shared_key = get_random_bytes(16)
print(shared_key)

pubkey_list_read = open(pubkey_list_address, "r")
pubkey_list_file = pubkey_list_read.read()

privkey_read = open(priv_key_address, "r")
privkey_file = privkey_read.read()

sign_priv_key = RSA.importKey(privkey_file)

timestamp = int(time.time()*1000000)
timestamp_str = str(timestamp)
print(timestamp)


### Use ISO 11770-3/2 instead 3/3
for PARTICIPANT in PARTICIPANT_LIST:
    pubkey_list = pubkey_list_file.split("user:")
    print(pubkey_list)
    pubkey_list.pop(0)
    for key in pubkey_list:
        # print(key)
        if key[0] == PARTICIPANT:
            get_key = key.split("pubkey:")
            key_str = get_key[1]
            print(key_str)

    pubkey = RSA.importKey(key_str)
    p_text = INITIATOR_ID.encode(encoding='utf_8') + shared_key
    RSA_cipher = PKCS1_OAEP.new(pubkey)
    c_text = RSA_cipher.encrypt(p_text)

    p_signed_text = (PARTICIPANT + timestamp_str).encode(encoding='utf_8') + c_text
    h_signed_text = SHA256.new()
    h_signed_text.update(p_signed_text)

    signer = PKCS1_v1_5.new(sign_priv_key)
    sig = signer.sign(h_signed_text)

    key_message = timestamp_str.encode(encoding='utf_8') + c_text + sig
    print(key_message)

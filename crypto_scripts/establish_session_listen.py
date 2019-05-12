# Responsible for initiating communication with the entire group.
# For all the members that join, there has to be one initiator.
# This listen file in essence listens to outgoing communication from the initiator
# This file finds the originer's public key and their own encrypted private key
# 

import sys, getopt, os
import time
from base64 import b64encode
from Crypto.Signature import PKCS1_PSS
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from netsim.netinterface import network_interface

NET_PATH = './'
pubkey_list_address = 'SETUP/pubkey_list.txt'

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hi:a:p:', longopts=['help', 'initiator=', 'addr=','passphrase:'])
except getopt.GetoptError:
	print('Usage: python establish_session_listen.py -i <initiator id> -a <own addr> -p <passphrase>')
	sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python establish_session_listen.py -i <initiator id> -a <own addr> -p <passphrase>')
        sys.exit(0)
    elif opt == '-i' or opt == '--initiator':
        INITIATOR_ID = arg
    elif opt == '-a' or opt == '--addr':
        OWN_ADDR = arg
    elif opt == '-p' or opt == '--pass':
        PASS = arg

if len(opts) != 3:
    print('Usage: python establish_session_listen.py -i <initiator id> -a <own addr> -p <passphrase>')

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)

#Import private user's key
priv_key_address = "SETUP/rsa_privkey_"+ OWN_ADDR +".pem"
privkey_read = open(priv_key_address, "r")
privkey_file = privkey_read.read()
privkey_read.close()

#Import public key list
pubkey_list_read = open(pubkey_list_address, "r")
pubkey_list_file = pubkey_list_read.read()
pubkey_list_read.close()

def save_shared_key(shared_key, pubkey, OWN_ADDR, NET_PATH):
	addr_dir = NET_PATH + OWN_ADDR + '/shared_key'
	if not os.path.exists(addr_dir):
		print('Folder for address ' + addr_dir + ' does not exist. Trying to create it... ', end='')
		os.mkdir(addr_dir)
	f=open(addr_dir+"/shared_enc_key.txt", "wb")
	RSA_cipher = PKCS1_OAEP.new(pubkey)
	enc_shared_key = RSA_cipher.encrypt(shared_key.encode(encoding='utf_8'))
	f.write(enc_shared_key)

# Get signer's public key
pubkey_list = pubkey_list_file.split("user:")
print(pubkey_list)
pubkey_list.remove("")
checker = 0

for key in pubkey_list:
    if key[0] == INITIATOR_ID:
        checker+=1
        get_key = key.split("pubkey:")
        key_str = get_key[1]
        print(key_str)
if checker == 0:
    print("No such public key string found!")
else:
    sign_pub_key = RSA.importKey(key_str)

netif = network_interface(NET_PATH, OWN_ADDR)
print('Main loop started...')

# Verifying Signature and saving content of message
while True:
    status, shared_key_message = netif.receive_msg(blocking=True)

    timestamp = shared_key_message[:16]
    c_text = shared_key_message[16:272]
    signature = shared_key_message[272:]
    # print(timestamp)
    # print(c_text)
    # print(signature)

    #Signed plaintext
    p_signed_text = OWN_ADDR.encode(encoding='utf_8')+ timestamp + c_text
    h_signed_text = SHA256.new()
    h_signed_text.update(p_signed_text)
    verifier = PKCS1_v1_5.new(sign_pub_key)
    verified = verifier.verify(h_signed_text, signature)
    if verified:
        print ("Successfully verified signature!")
        try:
            privkey = RSA.importKey(privkey_file, passphrase=PASS)
        except ValueError:
            print("Passphrase Wrong!")
            break
        privkey = RSA.importKey(privkey_file, passphrase=PASS)
        RSA_cipher = PKCS1_OAEP.new(privkey)

        #Decrypt here
        p_text = RSA_cipher.decrypt(c_text).decode(encoding = 'utf_8')
        print(p_text)
        if p_text[0] == INITIATOR_ID:
            save_shared_key(p_text[1:], sign_pub_key, OWN_ADDR,NET_PATH)
            print("Session Established!")
            # save key here
            break
        else:
            print("Decryption failed!")
    else:
        print("Signature verification failed!")

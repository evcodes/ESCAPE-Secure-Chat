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
# OWN_ADDR = 'C'
# INITIATOR_ID = 'A'
pubkey_list_address = 'SETUP/pubkey_list.txt'

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hi:a:', longopts=['help', 'initiator=', 'addr='])
except getopt.GetoptError:
	print('Usage: python establish_session_listen.py -i <initiator id> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python establish_session_listen.py -i <initiator id> -a <own addr>')
		sys.exit(0)
	elif opt == '-i' or opt == '--initiator':
		INITIATOR_ID = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg

if len(opts) != 2:
    print('Usage: python establish_session_listen.py -i <initiator id> -a <own addr>')



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
while True:
    status, shared_key_message = netif.receive_msg(blocking=True)

    timestamp = shared_key_message[:16]
    c_text = shared_key_message[16:272]
    signature = shared_key_message[272:]
    print(timestamp)
    print(c_text)
    print(signature)

    p_signed_text = OWN_ADDR.encode(encoding='utf_8')+ timestamp + c_text
    h_signed_text = SHA256.new()
    h_signed_text.update(p_signed_text)
    verifier = PKCS1_v1_5.new(sign_pub_key)
    verified = verifier.verify(h_signed_text, signature)
    if verified:
        print ("Successfully verified signature!")
        privkey = RSA.importKey(privkey_file)
        RSA_cipher = PKCS1_OAEP.new(privkey)
        p_text = RSA_cipher.decrypt(c_text).decode(encoding = 'utf_8')
        print(p_text)
        if p_text[0] == INITIATOR_ID:
            print("Decryption verified")
            print("Session Established!")
            # save key here
            break
        else:
            print("Decryption failed!")
    else:
        print("Signature verification failed!")
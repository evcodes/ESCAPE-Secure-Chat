#!/usr/bin/env python3
#receiver.py

'''
ALGO TO RECEIVE MESSAGE
0. Import own private key and sender public key
	to import your own private key, you must read in the file and use the password
	in order to import the RSA private key
1. Read the message, parse the content
2. Verify sequence number is greater than rcvstate
3. Verify signature using sender's pubkey
4. Get shared key, use your own privkey to decrypt shared key
5. Decrypt the content of the message using the shared key
6. Update the rcv state
'''

import os, sys, getopt, time
from netinterface import network_interface
from decrypt import decrypt_message
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from util import *

NET_PATH = './'

PARTICIPANT_LIST = 'ABC'
pubkey_list_address = 'SETUP/pubkey_list.txt'
PASS= ''

def get_sender(statefile):
	ifile = open(statefile,'r')
	line = ifile.readline()
	max_sqn = line[len("rcvsqn: "):]

	ifile.close()

	print(max_sqn)

	directory = os.listdir("./" + OWN_ADDR+"/IN/")

	for f in directory:
		if f[0:4] == max_sqn:
			print(f)
			return f[6:7]

# ------------       
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:k:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python receiver.py -p <network path> -a <own addr> -k <unique pw>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python receiver.py -p <network path> -a <own addr> -k <unique pw>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg
	elif opt == '-k':
		PASS = arg

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)

print('Main loop started...')

while True:
	privkey_file = "SETUP/rsa_privkey_" + OWN_ADDR + ".pem"

	f = open("./"+ OWN_ADDR + "/shared_key/shared_key.txt", 'rb')
	sym_key = f.read()
	f.close()
	
	state = "./"+ OWN_ADDR+"/rcvstate.txt"
	src = get_sender(state)

	# lookup public key and verify
	pubkey_read = open(pubkey_list_address, 'r')
	pubkey = pubkey_read.read()
	pubkey_read.close()

	found = False
	own_priv_key = read_priv_key(OWN_ADDR, PASS)

	print(own_priv_key)

	RSA_cipher = PKCS1_OAEP.new(own_priv_key)
	print(type(sym_key))
	print(sym_key)
	shared_key = RSA_cipher.decrypt(sym_key)

	print("Source",src)
	sender_pub_key = read_public_key(src)


# Calling receive_msg() in non-blocking mode ... 
	status, msg = netif.receive_msg(blocking=False)

	if status:
		# msg = decrypt_message(msg, "./" + OWN_ADDR + "/rcvstate.txt", "./" + OWN_ADDR + "/rsa_pubkey.pem")    
		print(decrypt_message(msg, state, shared_key, sender_pub_key))      # if status is True, then a message was returned in msg
	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message 
	print("msg", decrypt_message(msg, state, shared_key, sender_pub_key).decode('utf-8'))
	# print(decrypt_message)
	# print("msg: ",msg)
	# print("state: ",state)
	# print("shared_key: ", shared_key)
	# print("sender_pub_key: ", sender_pub_key)
	
	# print(decrypt_message(msg, state, shared_key, sender_pub_key))
	
	
	# print(msg[0:4])# Sqn number
	# print(msg[4:260]) # signature
	# print(msg[260:260+AES.block_size]) # nonce
	# print( msg[260+AES.block_size:]) # content

    

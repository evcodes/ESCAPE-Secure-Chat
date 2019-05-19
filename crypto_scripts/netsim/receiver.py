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

PARTICIPANT_LIST = ''
pubkey_list_address = 'SETUP/pubkey_list.txt'
PASS= ''

def clean():
	print("cleaning....")
	

def get_sender(statefile):
	ifile = open(statefile,'r')
	line = ifile.readline()
	max_sqn = line[len("sqn: "):]
	ifile.close()

	directory = os.listdir("./" + OWN_ADDR+"/IN/")

	for f in directory:
		if f[0:4] == max_sqn:
			print(f)
			return f[6:7]

# ------------       
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:k:l:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python receiver.py -p <network path> -a <own addr> -k <unique pw> -l <address_list>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python receiver.py -p <network path> -a <own addr> -k <unique pw> -l <address_list>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg
	elif opt == '-k':
		PASS = arg
	elif opt == '-l':
		PARTICIPANT_LIST = arg

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
	# if KeyboardInterrupt:
	# 	print('Interrupted')
	# 	clean()
	# 	try:
	# 		sys.exit(0)
	# 	except SystemExit:
	# 		os._exit(0)
	

# Calling receive_msg() in non-blocking mode ... 
	status, msg = netif.receive_msg(blocking=False)
	
	if status:
		privkey_file = "SETUP/rsa_privkey_" + OWN_ADDR + ".pem"

		f = open("./"+ OWN_ADDR + "/shared_key/shared_key.txt", 'rb')
		sym_key = f.read()
		f.close()
		
		state = "./"+ OWN_ADDR+"/state.txt"
		src = get_sender(state)

		ifIncreaseSeq = (src != OWN_ADDR)

		# lookup public key and verify
		pubkey_read = open(pubkey_list_address, 'r')
		pubkey = pubkey_read.read()
		pubkey_read.close()

		found = False
		own_priv_key = read_priv_key(OWN_ADDR, PASS)

		RSA_cipher = PKCS1_OAEP.new(own_priv_key)
		shared_key = RSA_cipher.decrypt(sym_key)
		sender_pub_key = read_public_key(src)

		# msg = decrypt_message(msg, "./" + OWN_ADDR + "/rcvstate.txt", "./" + OWN_ADDR + "/rsa_pubkey.pem")    
		print(src + ": " + decrypt_message(ifIncreaseSeq, msg, state, shared_key, sender_pub_key))      # if status is True, then a message was returned in msg
	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
	status, msg = netif.receive_msg(blocking=True) 


	
	privkey_file = "SETUP/rsa_privkey_" + OWN_ADDR + ".pem"

	f = open("./"+ OWN_ADDR + "/shared_key/shared_key.txt", 'rb')
	sym_key = f.read()
	f.close()
	
	state = "./"+ OWN_ADDR+"/state.txt"
	print(state)
	src = get_sender(state)
	print(src)
	
	ifIncreaseSeq = (src != OWN_ADDR)

	# lookup public key and verify
	pubkey_read = open(pubkey_list_address, 'r')
	pubkey = pubkey_read.read()
	pubkey_read.close()

	found = False
	own_priv_key = read_priv_key(OWN_ADDR, PASS)

	RSA_cipher = PKCS1_OAEP.new(own_priv_key)
	shared_key = RSA_cipher.decrypt(sym_key)
	sender_pub_key = read_public_key(src)
   # when returns, status is True and msg contains a message 
	print(src +": "+ decrypt_message(ifIncreaseSeq,msg, state, shared_key, sender_pub_key))

    

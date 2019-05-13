#!/usr/bin/env python3
#sender.py

import os, sys, getopt, time
from netinterface import network_interface
from encrypt_and_send import encrypt_message
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

NET_PATH = './'
OWN_ADDR = 'A'
password =''

# ------------       
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:k:', longopts=['help', 'path=', 'addr=', 'pass='])
except getopt.GetoptError:
	print('Usage: python sender.py -p <network path> -a <own addr> -k <secret key>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python sender.py -p <network path> -a <own addr> -k <password>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg
	elif opt == '-k' or opt == '--pass':
		password = arg

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
	msg = input('Type a message: ')
	dst = '+'
	path = "./" + OWN_ADDR + "/shared_key"

	# To make this work we need to request a password before every message is sent. This 
	# password must be the same as the initial password to send a message. This password 
	# will be used to decrypt the shared enc/dec key and will allow us to encrypt/decrypt the mssage
	# before sending.

	privkey_file = "SETUP/rsa_privkey_" + OWN_ADDR + ".pem"

	# Read shared key file and decrypt
	try:
		f = open(privkey_file, 'rb')
		# Use this for signing
		key = RSA.importKey(f.read(), password) 
		f.close()
	except ValueError:
		print( "Incorrect Password!!")
		break

	RSA_cipher = PKCS1_OAEP.new(key)

	f = open("./"+ OWN_ADDR + "/shared_key/shared_key.txt", 'rb')
	sym_key = f.read()
	f.close()

	shared_key = RSA_cipher.decrypt(sym_key)
	enc = encrypt_message(msg, "./" + OWN_ADDR + "/sndstate.txt", shared_key, key)
	netif.send_msg(dst, enc)

	if input('Continue? (y/n): ') == 'n': 
		break

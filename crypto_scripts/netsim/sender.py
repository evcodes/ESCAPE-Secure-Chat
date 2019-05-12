#!/usr/bin/env python3
#sender.py

import os, sys, getopt, time
from netinterface import network_interface
from encrypt_and_send import encrypt_message
from Crypto.PublicKey import RSA

NET_PATH = './'
OWN_ADDR = 'A'

# ------------       
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python sender.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python sender.py -p <network path> -a <own addr>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg

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
	dst = input('Type a destination address: ')
	path = "./" + OWN_ADDR + "/shared_key"

	# To make this work we need to request a password before every message is sent. This 
	# password must be the same as the initial password to send a message. This password 
	# will be used to decrypt the shared enc/dec key and will allow us to encrypt/decrypt the mssage
	# before sending.

	encryption_key = 
	enc = encrypt_message(msg, "./" + OWN_ADDR + "/sndstate.txt", "./" + OWN_ADDR + "/rsa_privkey.pem")
	
	netif.send_msg(dst, enc)

	if input('Continue? (y/n): ') == 'n': break

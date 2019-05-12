#!/usr/bin/env python3
#receiver.py

import os, sys, getopt, time
from netinterface import network_interface
from decrypt import decrypt_message

NET_PATH = './'
OWN_ADDR = ''
PARTICIPANT_LIST = 'ABC'
pubkey_list_address = 'SETUP/pubkey_list.txt'

def get_sender(statefile):
	ifile = open(statefile,'r')
	line = ifile.readline()
	max_sqn = line[len("rcvsqn: "):]

	ifile.close()
	print (max_sqn)

	directory = os.listdir("./" + OWN_ADDR+"/IN/")

	for f in directory:
		if f[0:4] == max_sqn:
			return f[6:7]

# ------------       
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python receiver.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python receiver.py -p <network path> -a <own addr>')
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

	src = get_sender('./'+ OWN_ADDR+"/rcvstate.txt")

	# lookup public key and verify
	pubkey_read = open(pubkey_list_address, 'r')
	pubkey = pubkey_read.read()
	pubkey_read.close()

	for PARTICIPANT in PARTICIPANT_LIST:
		pubkey_list = pubkey.split("user:")
# Calling receive_msg() in non-blocking mode ... 
	status, msg = netif.receive_msg(blocking=False)

	if status:
		# msg = decrypt_message(msg, "./" + OWN_ADDR + "/rcvstate.txt", "./" + OWN_ADDR + "/rsa_pubkey.pem")    
		print(msg)      # if status is True, then a message was returned in msg
	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message 
	print(msg)
    

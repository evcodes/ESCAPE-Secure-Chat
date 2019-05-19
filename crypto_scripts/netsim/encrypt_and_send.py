import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
from sign import generate_signature
from base64 import b64encode,b64decode
from util import *

'''
ALGO for encrypting a message
    1. Generate nonce and use as IV for CBC [x]
    2. Used private key that is shared amongst members of chat to encrypt the message
    3. Find out the sequence number in the user's state file and increment the counter by 1
    4. Build out the message structure
    5. Sign the message with sender's private key
    6. Send the message to the server
'''

def read_state(statefile):  
    ifile = open(statefile, 'rt')
    # Get sqn num
    line = ifile.readline()
    sqn = (line[len("sqn: "):])
    sqn = int(sqn, base=10)
    ifile.close()
    return (sqn)

def update_state(sqn,statefile):
    state = "sqn: " + str(pad_num(sqn + 1))
    ofile = open(statefile, 'wt')
    ofile.write(state)
    ofile.close()
    
def generate_nonce():
    nonce = get_random_bytes(AES.block_size)
    return nonce

# Ensures that there are 4 digits so we have some kind of standard length of sequence numbers
# Reset after we reach 9999 messages 

def encrypt_message(m,statefile,shared_key,privkey):

    plaintext = m.encode('utf-8')
    sqn = read_state(statefile)
    nonce = generate_nonce()

    cipher = AES.new(shared_key, AES.MODE_CBC, nonce)
    plaintext = Padding.pad(plaintext, AES.block_size, style = 'pkcs7')

    # dec_cipher = AES.new(shared_key, AES.MODE_CBC, nonce)
    ciphertext = cipher.encrypt(plaintext)

    sqn_num = str(pad_num(sqn)).encode('utf-8')

    sign_content = sqn_num+nonce+ciphertext
    sign = generate_signature(sign_content,privkey)

    # update_state(sqn,statefile)
    sqn = pad_num(sqn)
    sqn = str(sqn).encode('utf-8')

    # This is the setup of our file
    return (sqn + sign + nonce + ciphertext)
    
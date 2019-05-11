import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from sign import generate_signature

inputfile = ""
outputfile = ""

'''
Steps for sending a message
    1. Generate nonce and use as IV for CBC [x]
    2. Used private key that is shared amongst members of chat to encrypt the message
    3. Find out the sequence number in the user's state file and increment the counter by 1
    4. Build out the message structure
    5. Sign the message with sender's private key
    6. Send the message to the server
'''

def read_state(statefile):
    # Get encryption key
    ifile = open(statefile, 'rt')
    line = ifile.readline()
    enckey = line[len("enckey: "):len("enckey: ") + 32]
    enckey = bytes.fromhex(enckey)

    # Get sqn num
    line = ifile.readline()
    sndsqn = (line[len("sndsqn: "):])
    
    sndsqn = int(sndsqn, base=10)
    print(sndsqn)
    ifile.close()
    return (enckey,sndsqn)

def update_state(sndsqn,statefile):

    ifile = open(statefile, 'rt')
    line = ifile.readline()
    enckey = line[len("enckey: "):len("enckey: ") + 32] +"/n"

    state = "sndsqn: " + str(sndsqn + 1)
    ofile = open(statefile, 'wt')
    ofile.write(enckey + state)
    ofile.close()
    
def generate_nonce():
    nonce = get_random_bytes(AES.block_size)
    return nonce

nonce = generate_nonce()

# Ensures that there are 4 digits so we have some kind of standard length of sequence numbers
# Reset after we reach 9999 messages 
def pad_sqn(sqn):
    print("{:04d}".format(sqn))
    return ("{:04d}".format(sqn))

def encrypt_message(m,statefile,privkey):

    plaintext = m.encode('utf-8')
    key,sqn = read_state(statefile)

    cipher = AES.new(key, AES.MODE_CBC, nonce)
    content = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(content)
    sign = generate_signature(ciphertext,privkey)
    
    update_state(sqn,statefile)
    sqn = pad_sqn(sqn)
    sqn = str(sqn).encode('utf-8')
    
    return (sqn + sign + nonce + ciphertext)
    
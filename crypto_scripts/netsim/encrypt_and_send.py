import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from sign import generate_signature


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
    ifile = open(statefile, 'rt')

    # Get sqn num
    line = ifile.readline()
    sndsqn = (line[len("sndsqn: "):])
    sndsqn = int(sndsqn, base=10)
    ifile.close()
    return (sndsqn)

def update_state(sndsqn,statefile):
    state = "sndsqn: " + str(sndsqn + 1)
    ofile = open(statefile, 'wt')
    ofile.write(state)
    ofile.close()
    
def generate_nonce():
    nonce = get_random_bytes(AES.block_size)
    return nonce

nonce = generate_nonce()

# Ensures that there are 4 digits so we have some kind of standard length of sequence numbers
# Reset after we reach 9999 messages 
def pad_sqn(sqn):
    return ("{:04d}".format(sqn))

def encrypt_message(m,statefile,shared_key,privkey):

    plaintext = m.encode('utf-8')
    sqn = read_state(statefile)

    cipher = AES.new(shared_key, AES.MODE_CBC, nonce)
    content = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(content)
    
    sign_content = str(sqn).encode('utf-8')+nonce+ciphertext

    sign = generate_signature(sign_content,privkey)
    update_state(sqn,statefile)
    sqn = pad_sqn(sqn)
    sqn = str(sqn).encode('utf-8')

    print(len(sign))

    
    
    return (sqn + sign + nonce + ciphertext)
    
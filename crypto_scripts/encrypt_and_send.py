import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from sign import generate_signature

statefile = "sndstate.txt"
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

def read_priv_key():
    data = open("shared_privkey.bin","rb").read()
    return data

def read_state():
    # Get encryption key
    ifile = open(statefile, 'rt')
    line = ifile.readline()
    enckey = line[len("enckey: "):len("enckey: ") + 32]
    enckey = bytes.fromhex(enckey)

    # Get sqn num
    line = ifile.readline()
    sndsqn = line[len("sndsqn: "):]
    sndsqn = int(sndsqn, base=10)
    ifile.close()
    return (enckey,sndsqn)

def read_message():
    ifile = open(inputfile,'rt')
    content = ifile.read()
    ifile.close()
    return content

def update_state(enckey,sndsqn):
    state = "enckey: " + enckey.hex() + '\n'
    state = state + "sndsqn: " + str(sndsqn + 1)
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
    print("{:04d}".format(sqn))
    return ("{:04d}".format(sqn))

def encrypt_message():
    result = read_message()
    plaintext = result.encode('utf-8')
    key,sqn = read_state()

    cipher = AES.new(key, AES.MODE_CBC, nonce)
    content = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(content)
    sign = generate_signature(content.decode('utf-8'))
    
    update_state(key, sqn)
    sqn = pad_sqn(sqn)
    sqn = str(sqn).encode('utf-8')
    print(len(sqn)) # 4 bytes
    print(len(sign)) # 256 bytes
    print(len(nonce)) # 16 bytes
    
    build_message(sqn + sign + nonce + ciphertext)
    

def build_message(content):
    '''
    _______________________
    |___|sequence|signature|
    |________Nonce_________|
    |                      |  
    |       Message        |
    |______________________|
    |____________|pad|p.len|
    '''
    
    ofile = open("./"+outputfile, 'wb')
    ofile.write(content)
    ofile.close()

try:
    opts, args = getopt.getopt(sys.argv[1:],'hi:o:')
except getopt.GetoptError:
    print("Usage: encrypt_and_send.py -i <inputfile> -o <outputfile>")
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        print("Usage: encrypt_and_send.py -i <inputfile> -o <outputfile>")
        sys.exit()
    elif opt == '-i':
        inputfile = arg
    elif opt == '-o':
        outputfile = arg

if len(inputfile) == 0:
    print("Error: Name of input file is missing.")
    sys.exit(2)

if len(outputfile) == 0:
    print("Error: Name of output file is missing.")
    sys.exit(2)

    print('Encrypting...\n', end='')

encrypt_message()
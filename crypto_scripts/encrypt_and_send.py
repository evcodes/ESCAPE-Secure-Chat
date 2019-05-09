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
    sndsqn = line[len("sndsqn: "):]
    sndsqn = int(sndsqn, base=10)
    ifile.close()
    return (enckey,sndsqn)
    
def generate_nonce():
    nonce = get_random_bytes(AES.block_size)
    return nonce

nonce = generate_nonce()

def encrypt_message(m):
    plaintext = m.encode('utf-8')
    key,sqn = read_state()
    cipher = AES.new(key, AES.MODE_CBC, nonce)
    content = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(content)

    sign = generate_signature(content)

    return (sqn + sign + nonce + ciphertext)

def build_message(seq,sign,nonce,enc_m):
    '''
    _______________________
    |___|sequence|signature|
    |________Nonce_________|
    |                      |  
    |       Message        |
    |______________________|
    |____________|pad|p.len|
    '''
    



    return ("Hello")


def decrypt_message(inputfile):
    f = open(inputfile, 'rb')
    ciphertext = f.read()
    f.close()

    # separate the initial value from the encrypted plaintext in the ciphertext
    iv = ciphertext[:AES.block_size]
    cipher_text = ciphertext[AES.block_size:]

    # create AES cipher object
    key = keystring.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # decrypt ciphertext
    plaintext = cipher.decrypt(cipher_text)
    plaintext = Padding.unpad(plaintext, AES.block_size)

    print(plaintext.decode('utf-8'))

    # write out the plaintext obtained into the output file
    out = open(outputfile, 'wb')
    out.write(plaintext)
    out.close()

statefile = "sndstate.txt"
inputfile = ""
outputfile = ""

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



encrypt_message("Hello World")


#     f = open(inputfile, 'rb')
#     plaintext = f.read()
#     f.close

#     plaintext = Padding.pad(plaintext, AES.block_size)
#     key = keystring.encode('utf-8')

#     # Generate an initial value
#     iv = get_random_bytes(AES.block_size)
#     
#     # plaintext = plaintext.encode('utf-8')
#     

#     print('IV: ', iv.hex())
#     print('Ciphertext: ', ciphertext.hex(), "\n")

#     ofile = open(outputfile, 'wb')
#     ofile.write(iv+ciphertext)
#     ofile.close()

# else:
#     print('Decrypting...\n', end='')

#     # read the saved nonce and the ciphertext from the input file
    # f = open(inputfile, 'rb')
    # ciphertext = f.read()
    # f.close()

    # # separate the initial value from the encrypted plaintext in the ciphertext
    # iv = ciphertext[:AES.block_size]
    # cipher_text = ciphertext[AES.block_size:]

    # # create AES cipher object
    # key = keystring.encode('utf-8')
    # cipher = AES.new(key, AES.MODE_CBC, iv)

    # # decrypt ciphertext
    # plaintext = cipher.decrypt(cipher_text)
    # plaintext = Padding.unpad(plaintext, AES.block_size)

    # print(plaintext.decode('utf-8'))

    # # write out the plaintext obtained into the output file
    # out = open(outputfile, 'wb')
    # out.write(plaintext)
    # out.close()

# print('Done.')
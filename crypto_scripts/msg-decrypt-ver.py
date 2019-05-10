import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from sign import generate_signature

statefile = "rcvstate.txt"
inputfile = ""
outputfile = ""

def read_state():
    # Get decryption key
    ifile = open(statefile, 'rt')
    line = ifile.readline()
    deckey = line[len("deckey: "):len("deckey: ") + 32]
    deckey = bytes.fromhex(deckey)

    #Get sqn number
    line = ifile.readline()
    rcvsqn = line[len("rcvsqn: "):]
    rcvsqn = int(rcvsqn, base =10)
    ifile.close()
    return (deckey,rcvsqn)
    
def decrypt_message():
    f = open(inputfile, 'rb')
    ciphertext = f.read()
    f.close()

    # separate the initial value from the encrypted plaintext in the ciphertext
    iv = ciphertext[:AES.block_size]
    # cipher_text = ciphertext[AES.block_size:]

    # create AES cipher object
    key,sqn = read_state()
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # decrypt ciphertext
    plaintext = cipher.decrypt(cipher_text)
    plaintext = Padding.unpad(plaintext, AES.block_size)

    print(plaintext.decode('utf-8'))

    # write out the plaintext obtained into the output file
    out = open(outputfile, 'wb')
    out.write(plaintext)
    out.close()


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

# print('Done.')

try:
    opts, args = getopt.getopt(sys.argv[1:],'hi:o:')
except getopt.GetoptError:
    print("Usage: msg-decrypt-ver.py -i <inputfile> -o <outputfile>")
    sys.exit(2)

for opt, arg in opts:
    if opt == '-h':
        print("Usage: msg-decrypt-ver.py -i <inputfile> -o <outputfile>")
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


    print('Decrypting...\n', end='')

decrypt_message()

    
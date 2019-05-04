import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

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

def generate_nonce():
    nonce = get_random_bytes(AES.block_size)
    return nonce

nonce = generate_nonce()

def encrypt_message(m):
    key = read_priv_key()
    plaintext = m.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, nonce)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    build_message(000, nonce, ciphertext)

def build_message(seq,sign,nonce,enc_m):
    print("hello")




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
#     f = open(inputfile, 'rb')
#     ciphertext = f.read()
#     f.close()

#     # separate the initial value from the encrypted plaintext in the ciphertext
#     iv = ciphertext[:AES.block_size]
#     cipher_text = ciphertext[AES.block_size:]

#     # create AES cipher object
#     key = keystring.encode('utf-8')
#     cipher = AES.new(key, AES.MODE_CBC, iv)

#     # decrypt ciphertext
#     plaintext = cipher.decrypt(cipher_text)
#     plaintext = Padding.unpad(plaintext, AES.block_size)

#     print(plaintext.decode('utf-8'))

#     # write out the plaintext obtained into the output file
#     out = open(outputfile, 'wb')
#     out.write(plaintext)
#     out.close()

# print('Done.')
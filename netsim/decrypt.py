import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
import sign

def verify_sqn(msg_sqn,rcv_state):
    msg_sqn = msg_sqn.decode('utf-8')
    return int(msg_sqn) > rcv_state
    
def read_state(statefile):
    # Get decryption key
    ifile = open(statefile, 'rt')
    line = ifile.readline()
    deckey = line[len("deckey: "):len("deckey: ") + 32]


    #Get sqn number
    line = ifile.readline()
    rcvsqn = line[len("rcvsqn: "):]
    rcvsqn = int(rcvsqn, base =10)
    ifile.close()
    return (deckey,rcvsqn)
    
def decrypt_message(msg,statefile,pubkey):
    
    key, rcv = read_state(statefile)
    ## If message number is not greater than the one in our state file, do not decrypt
    
    # Seperate parts of the message
    signature = msg[4:4+256]
    nonce = msg[260:260 + AES.block_size]

    print(len(nonce))
    cipher_text = msg[260+AES.block_size:]


    # create AES cipher object
    cipher = AES.new(key, AES.MODE_CBC, nonce)

    # Verify Sqn number
    if(verify_sqn(msg[0:4],rcv) is False): 
        return 

    # decrypt ciphertext
    plaintext = cipher.decrypt(cipher_text)

    # Verify Signature
    sign.verify_signature(signature,plaintext,pubkey)

    plaintext = unpad(plaintext, AES.block_size)
    return(plaintext.decode('utf-8'))
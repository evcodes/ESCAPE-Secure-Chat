import sys, getopt
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
from util import verify_signature,pad_num

def verify_sqn(msg_sqn,rcv_state):
    msg_sqn = msg_sqn.decode('utf-8')
    return int(msg_sqn) == rcv_state
    
def read_state(statefile):
    #Get sqn number
    ifile = open(statefile,'r')
    line = ifile.readline()
    sqn = line[len("sqn: "):]
    sqn = int(sqn, base =10)
    ifile.close()
    return (sqn)

def update_state(statefile,sqn):
    state = "sqn: " + str(pad_num(sqn + 1))
    ofile = open(statefile, 'wt')
    ofile.write(state)
    ofile.close()
    
def decrypt_message(ifIncrease,msg,statefile,sharedkey, pubkey):
    rcv = read_state(statefile)
    ## If message number is not greater than the one in our state file, do not decrypt
    # Seperate parts of the message
    
    sqn = msg[0:4]
    signature = msg[4:4+256]
    nonce = msg[260:260 + AES.block_size]
    cipher_text = msg[260+AES.block_size:]

     # Verify Sqn number
    if(verify_sqn(sqn,rcv) is False): 
        return ("Sequence number verification failed")
 

    content = sqn + nonce + cipher_text
    is_verified = verify_signature(content, signature, pubkey)

    if  (is_verified == False):
        print("Verification failed")
        return 

    # Create AES CIPHER 
    cipher = AES.new(sharedkey, AES.MODE_CBC, nonce)

    # decrypt ciphertext
    plaintext = cipher.decrypt(cipher_text)
    plain = Padding.unpad(plaintext,AES.block_size, style = 'pkcs7')

    # plaintext = unpad(plaintext, AES.block_size)
    update_state(statefile, rcv)
    return(plain.decode('utf-8'))
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5


#given n -> pad with sufficient 0's to have 4 digis
def pad_num(n):
    return ("{:04d}".format(n))

def read_priv_key(OWN_ADDR, pw):
    priv_key_address = "./SETUP/rsa_privkey_" + OWN_ADDR + ".pem"
    privkey_read = open(priv_key_address, "r")
    privkey_file = privkey_read.read()
    privkey_read.close()

    try:
        p_key = RSA.importKey(privkey_file, pw)
    except ValueError:
        print("Passphrase wrong")
        return
    return p_key

def read_public_key(ADDR):

    '''
    Split up the directory and traverse the list of users
    when you find the user, import the key and return it.
    '''
    pubkey_list_address = './SETUP/pubkey_list.txt'
    pubkey_list_read = open(pubkey_list_address, "r")
    pubkey_list_file = pubkey_list_read.read()
    pubkey_list_read.close()

    pubkey_list = pubkey_list_file.split("user:")
    pubkey_list.remove("")
    found = False
    for key in pubkey_list:
        if (key[0] == ADDR and found == False):
            found = True
            get_key = key.split("pubkey:")            
            key_str = get_key[1]
            break

    if found == False:
        print("No such public key was found")
        return

    return RSA.importKey(key_str)

def verify_signature(content, signature,pub_key):
    h = SHA256.new()
    h.update(content)

    verifier = PKCS1_v1_5.new(pub_key)
    verified = verifier.verify(h, signature)

    return verified
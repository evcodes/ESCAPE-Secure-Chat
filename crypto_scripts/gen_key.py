from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

# Generate the RSA key for every user

def gen_key_pair(passpharse):
    new_key = RSA.generate(bits, e=65537)
    return key.exportKey(passphrase=passphrase), key.publickey().exportKey()

def generate_RSA(bits=2048):
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    from Crypto.PublicKey import RSA


    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey(passphrase='this_is_C')

    file_out = open("rsa_privkey_C.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    file_out = open("rsa_pubkey_C.pem", "wb")
    file_out.write(public_key)
    file_out.close()
    return private_key, public_key

    # new_key = RSA.generate(bits, e=65537)
    # public_key = new_key.publickey().exportKey("PEM")
    # private_key = new_key.exportKey("PEM")
    #
    # file_out = open("rsa_privkey_B.pem", "wb")
    # file_out.write(private_key)
    # file_out.close()
    #
    # file_out = open("rsa_pubkey_B.pem", "wb")
    # file_out.write(public_key)
    # file_out.close()
    # return private_key, public_key
    #
    # new_key = RSA.generate(bits, e=65537)
    # public_key = new_key.publickey().exportKey("PEM")
    # private_key = new_key.exportKey("PEM")
    #
    # file_out = open("rsa_privkey_C.pem", "wb")
    # file_out.write(private_key)
    # file_out.close()
    #
    # file_out = open("rsa_pubkey_C.pem", "wb")
    # file_out.write(public_key)
    # file_out.close()
    # return private_key, public_key




# <<<<<<< HEAD
generate_RSA()
#
# def gen_shared_key():
#     file_out = open("shared_privkey.bin","wb")
#     file_out.write( get_random_bytes(16))
#     file_out.close()



# >>>>>>> fa48ca8975a9acb18c4f95ce16d9373accce6e03

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

def generate_RSA(bits=2048):
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    from Crypto.PublicKey import RSA
    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")

    file_out = open("rsa_privkey.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    file_out = open("rsa_pubkey.pem", "wb")
    file_out.write(public_key)
    file_out.close()
    return (private_key, public_key)


def gen_shared_key():
    file_out = open("shared_privkey.bin","wb")
    file_out.write( get_random_bytes(16))
    file_out.close()


def sample_hash(content):
    h = SHA256.new()
    h.update(content)

    print(h.hexdigest())
    # print(h.digest())

sample_hash(b'Some text to be hashed')
generate_RSA()

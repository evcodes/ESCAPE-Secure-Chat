import sys, getopt
from base64 import b64encode
from Crypto.Signature import PKCS1_PSS
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


def generate_signature(m):
    content = m.encode('utf-8')
    h = SHA256.new()
    h.update(content)

    private_key = False
    with open ("rsa_privkey.pem", "r") as myfile:
        private_key = RSA.importKey(myfile.read())

    
    signer = PKCS1_v1_5.new(private_key)
    sig = signer.sign(h)
    return sig

def verify_signature(signature, m):

    h = SHA256.new()
    # m.decode('utf-8')
    h.update(m)
    public_key = False

    with open ("rsa_pubkey.pem", "r") as myfile:
        public_key = RSA.importKey(myfile.read())
    
    verifier = PKCS1_v1_5.new(public_key)
    verified = verifier.verify(h, signature)
    print(type(verified))
    assert verified, 'Signature verification failed'
    print ('Successfully verified message')

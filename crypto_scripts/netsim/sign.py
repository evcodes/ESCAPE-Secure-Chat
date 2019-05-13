import sys, getopt
from base64 import b64encode
from Crypto.Signature import PKCS1_PSS
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def generate_signature(m,privkey):

    h = SHA256.new()
    h.update(m)
    
    signer = PKCS1_v1_5.new(privkey)
    sig = signer.sign(h)
    return sig

def verify_signature(signature, m, pubkey):

    h = SHA256.new()
    # m.decode('utf-8')
    h.update(m)
    public_key = False

    with open (pubkey, "r") as myfile:
        public_key = RSA.importKey(myfile.read())
    
    verifier = PKCS1_v1_5.new(public_key)
    verified = verifier.verify(h, signature)
  
    assert verified, 'Signature verification failed'
    print ('Successfully verified message')

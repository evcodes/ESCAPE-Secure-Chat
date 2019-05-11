import sys, getopt
from base64 import b64encode
from Crypto.Signature import PKCS1_PSS
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


message = "I want this stream signed"
temp = message.encode(encoding='utf_8')
h = SHA256.new()
h.update(temp)


private_key = False
with open ("rsa_privkey_A.txt", "r") as myfile:
    private_key = RSA.importKey(myfile.read())

public_key = False
with open ("rsa_pubkey_A.txt", "r") as myfile:
    public_key = RSA.importKey(myfile.read())

signer = PKCS1_v1_5.new(private_key)
sig = signer.sign(h)


verifier = PKCS1_v1_5.new(public_key)
verified = verifier.verify(h, sig)
assert verified, 'Signature verification failed'
print ('Successfully verified message')

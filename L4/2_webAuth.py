import os

# REGISTRATION (generate key pair)

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def register():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key


# SERVER DATABASE
server_db = {}

private_key, public_key = register()
print("\nPrivate Key Generated :",private_key)
print("\nPublic Key Generated  :",public_key)

server_db["user1"] = public_key #server stores public key


# fun to create random challenge by server and send to authenticator/user
def create_challenge():
    return os.urandom(32)




# SIGN CHALLENGE (Authenticator)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def sign_challenge(private_key, challenge):

    signature = private_key.sign(
        challenge,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return signature


# VERIFY SIGNATURE (Server)

def verify_signature(public_key, challenge, signature):

    try:

        public_key.verify(
            signature,
            challenge,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        print("Authentication Success")

    except Exception:

        print("Authentication Failed")


# FULL FLOW

challenge = create_challenge()

print("\n\nChallenge (hex):")
print(challenge.hex(), "\n")


print("\n==>Authenticator signs the challenge using PRIVATE KEY")

signature = sign_challenge(private_key, challenge) #now user will sign the challenge with pvt key
print("\nSignature Created")
print("\nSignature (first 64 hex chars):")
print(signature.hex()[:64], "...", "\n")

print("\n==>now verification ")
verify_signature(server_db["user1"], challenge, signature)


# SYMMETRIC AUTHENTICATION EXAMPLE

import hmac
import hashlib

def verify_hmac(secret, message, received_signature):

    expected_signature = hmac.new(secret, message, hashlib.sha256).digest()

    if hmac.compare_digest(expected_signature, received_signature):
        print("\nSymmetric Authentication Success")
    else:
        print("Symmetric Authentication Failed")





print("\n==>")
secret = b"networkSecurityLAB4"

message = b"be humble and kind"

signature = hmac.new(secret, message, hashlib.sha256).digest()

print("\nSymmetric Signature created:")
print(signature.hex())

verify_hmac(secret, message, signature)




#comparision
print("\n\n==> Now Comparision :")
import time

start = time.time()
signature = sign_challenge(private_key, challenge)
verify_signature(server_db["user1"], challenge, signature)
print("Asymmetric time:", (time.time() - start)*1000000)

start = time.time()
signature = hmac.new(secret, message, hashlib.sha256).digest()
verify_hmac(secret, message, signature)

print("Symmetric time:", (time.time() - start)*1000000)

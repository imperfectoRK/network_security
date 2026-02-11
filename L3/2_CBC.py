from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

block_size = 16

def pad(data):
     padLength=block_size-(len(data)%block_size) 
     padding=bytes([padLength])*padLength 
     return data+padding 

def unpad(data):
     padlength=data[-1] 
     return data[:-padlength]

key = b"midsem is coming"  
iv  = b"start  preparing"

cipher_enc = AES.new(key, AES.MODE_CBC, iv)
cipher_dec = AES.new(key, AES.MODE_CBC, iv)




def encryptfun(paddedPT):
    cipher_enc = AES.new(key, AES.MODE_CBC, iv)
    return cipher_enc.encrypt(paddedPT)


def decryptfun(ciphertext):
    cipher_dec = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher_dec.decrypt(ciphertext)
    return unpad(plaintext)



print("\n  cbc pattern test  ")

test_pt = b"A" * 32
test_padded = pad(test_pt)

ct = encryptfun(test_padded)

print(ct[:16])
print(ct[16:32])  # FALSE



print("\n 1st original message  ")

pt = b"from=alice______to=bob__________Amount=1000"
paddedPT = pad(pt)
ciphertext = encryptfun(paddedPT)

print("Plaintext:", pt)






print("\n 2nd attacker flips bits  ")

ct = bytearray(ciphertext)
index = pt.index(b"1000") - block_size


# locating position of '1' in "1000"
# flip '1' → '9' using xor

# get ASCII
original = ord('1')      # 0x31
desired  = ord('9')      # 0x39

# we need to flip
XOR_value = ord('1') ^ ord('9')

ct[index] ^= XOR_value





modifiedCT = bytes(ct)

print("\n 3rd victim decrypt  ")

modifiedPT = decryptfun(modifiedCT)
print("modified Plaintext:", modifiedPT)


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




# encryption function 
def encryptfun(paddedPT):

    # split plaintext into blocks
    blocks = []
    for i in range(0, len(paddedPT), block_size):
        blocks.append(paddedPT[i:i+block_size])

    prev = iv
    cblocks = []

    for b in blocks:

        # XOR plaintext block with previous ciphertext 
        xored = bytes([b[i] ^ prev[i] for i in range(block_size)])

        cipher = AES.new(key, AES.MODE_ECB)
        c = cipher.encrypt(xored)

        cblocks.append(c)

        prev = c   

    return b"".join(cblocks)



# decryption function 
def decryptfun(ciphertext):

    # split ciphertext into blocks
    blocks = []
    for i in range(0, len(ciphertext), block_size):
        blocks.append(ciphertext[i:i+block_size])

    prev = iv
    pblocks = []

    for b in blocks:

        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(b)

        # XOR with previous ciphertext 
        p = bytes([decrypted[i] ^ prev[i] for i in range(block_size)])

        pblocks.append(p)

        prev = b  

    return unpad(b"".join(pblocks))




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
# we need to flip
# flip '1' → '9' using xor
# get ASCII
original = ord('1')      # 0x31
desired  = ord('9')      # 0x39
XOR_value = ord('1') ^ ord('9')
ct[index] ^= XOR_value





modifiedCT = bytes(ct)

print("\n 3rd victim decrypt  ")

modifiedPT = decryptfun(modifiedCT)
print("modified Plaintext:", modifiedPT)


from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

block_size = 16

def pad(data):
    padLength = block_size - (len(data) % block_size)
    return data + bytes([padLength]) * padLength

def unpad(data):
    return data[:-data[-1]]

key = b"midsem is coming"   # 16 bytes
iv  = get_random_bytes(16)

cipher_enc = AES.new(key, AES.MODE_CBC, iv)
cipher_dec = AES.new(key, AES.MODE_CBC, iv)




def encryptblocks(paddedPT):
    blocks = []
    for i in range(0, len(paddedPT), block_size):
        blocks.append(paddedPT[i:i+block_size])

    ciphertext = cipher_enc.encrypt(b"".join(blocks))
    return ciphertext





def decryptblocks(ciphertext):
    plaintext = cipher_dec.decrypt(ciphertext)
    return unpad(plaintext)




print("\n  cbc pattern test  ")

test_pt = b"A" * 32
test_padded = pad(test_pt)

ct = encryptblocks(test_padded)

print(ct[:16])
print(ct[16:32])  # FALSE



print("\n 1st original message  ")

pt = b"from=alice______to=bob_______amount=1000____"
paddedPT = pad(pt)
ciphertext = encryptblocks(paddedPT)

print("Plaintext:", pt)






print("\n 2nd attacker flips bits  ")

ct = bytearray(ciphertext)

# locate byte position of '1' in "1000"
# flip '1' → '9' using xor
# ascii: '1' = 0x31, '9' = 0x39 → xor = 0x08

index = pt.index(b"1000") - block_size
ct[index] ^= 0x08

tampered_ciphertext = bytes(ct)




print("\n 3rd victim decrypt  ")

tampered_plaintext = decryptblocks(tampered_ciphertext)
print("Tampered Plaintext:", tampered_plaintext)


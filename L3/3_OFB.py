from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = b"midsem is coming"
iv  = b"start  preparing"

def encrypt(pt):
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    return cipher.encrypt(pt)

def decrypt(ct):
    cipher = AES.new(key, AES.MODE_OFB, iv=iv)
    return cipher.decrypt(ct)


print("\n  ofb pattern test  ")

test_pt = b"a" * 32
ct = encrypt(test_pt)

print(ct[:16])
print(ct[16:32])



#bit flip
print("\n 1st original message  ")

pt = b"user=rahul;access=read;token=100;"
ct = encrypt(pt)

print("plaintext:", pt)


print("\n 2nd  attacker flips bits  ")

ct_mod = bytearray(ct)

# change quota=100 -> quota=900
idx = pt.index(b"100")
original = ord('1')      
desired  = ord('9')      
XOR_value = ord('1') ^ ord('9')
ct_mod[idx] ^= XOR_value



modifiedCT = bytes(ct_mod)


print("\n 3rd victim decrypts  ")

modifiedPT = decrypt(modifiedCT)
print("modified plaintext:", modifiedPT)

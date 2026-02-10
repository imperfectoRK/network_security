from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = b"midsem is coming"
iv  = get_random_bytes(16)

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


print("\n 1st original message  ")

pt = b"user=rahul;access=read;token=100;"
ct = encrypt(pt)

print("plaintext:", pt)


print("\n 2nd  attacker flips bits  ")

ct_mod = bytearray(ct)

# change quota=100 -> quota=900
idx = pt.index(b"100")

# '1' (0x31) -> '9' (0x39) => xor 0x08
ct_mod[idx] ^= 0x08

tampered_ct = bytes(ct_mod)


print("\n 3rd victim decrypts  ")

tampered_pt = decrypt(tampered_ct)
print("tampered plaintext:", tampered_pt)

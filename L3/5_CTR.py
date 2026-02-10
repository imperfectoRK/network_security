from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = b"midsem is coming"
nonce = get_random_bytes(8)

def encrypt(pt):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.encrypt(pt)

def decrypt(ct):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ct)


print("\n  ctr pattern test  ")

test_pt = b"a" * 32
ct = encrypt(test_pt)

print(ct[:16])
print(ct[16:32])


print("\n1st original message  ")

pt = b"user=rahul;role=user;cmd=view;limit=10;"
ct = encrypt(pt)

print("plaintext:", pt)


print("\n 2nd  attacker flips bits  ")

ct_mod = bytearray(ct)

# role=user -> role=root
idx_role = pt.index(b"role=user") + len(b"role=")
ct_mod[idx_role+0] ^= ord("u") ^ ord("r")
ct_mod[idx_role+1] ^= ord("s") ^ ord("o")
ct_mod[idx_role+2] ^= ord("e") ^ ord("o")
ct_mod[idx_role+3] ^= ord("r") ^ ord("t")

# cmd=view -> cmd=kill
idx_cmd = pt.index(b"cmd=view") + len(b"cmd=")
ct_mod[idx_cmd+0] ^= ord("v") ^ ord("k")
ct_mod[idx_cmd+1] ^= ord("i") ^ ord("i")
ct_mod[idx_cmd+2] ^= ord("e") ^ ord("l")
ct_mod[idx_cmd+3] ^= ord("w") ^ ord("l")

tampered_ct = bytes(ct_mod)


print("\n 3rd victim decrypts  ")

tampered_pt = decrypt(tampered_ct)
print("tampered plaintext:", tampered_pt)

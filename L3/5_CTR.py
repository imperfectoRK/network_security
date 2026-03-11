from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = b"midsem is coming"


block_size = 16


# encryption function 
def encrypt(pt):

    blocks = []
    for i in range(0, len(pt), block_size):
        blocks.append(pt[i:i+block_size])

    cblocks = []
    counter = 0

    for b in blocks:

        # create 16-byte counter block
        counter_block = counter.to_bytes(16, 'big')

        cipher = AES.new(key, AES.MODE_ECB)
        keystream = cipher.encrypt(counter_block)

        # XOR plaintext with keystream
        c = bytes([b[i] ^ keystream[i] for i in range(len(b))])

        cblocks.append(c)

        counter += 1

    return b"".join(cblocks)



# decryption function 
def decrypt(ct):

    blocks = []
    for i in range(0, len(ct), block_size):
        blocks.append(ct[i:i+block_size])

    pblocks = []
    counter = 0

    for b in blocks:

        counter_block = counter.to_bytes(16, 'big')

        cipher = AES.new(key, AES.MODE_ECB)
        keystream = cipher.encrypt(counter_block)

        # XOR ciphertext with keystream
        p = bytes([b[i] ^ keystream[i] for i in range(len(b))])

        pblocks.append(p)

        counter += 1

    return b"".join(pblocks)




print("\n  ctr pattern test  ")

test_pt = b"a" * 32
ct = encrypt(test_pt)

print(ct[:16])
print(ct[16:32])


print("\n1st original message  ")

pt = b"user=rahul;role=user;cmd=view;limit=10;byebye"
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

modifiedCT = bytes(ct_mod)


print("\n 3rd victim decrypts  ")

modifiedPT = decrypt(modifiedCT)
print("tampered plaintext:", modifiedPT)

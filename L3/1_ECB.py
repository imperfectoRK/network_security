from Crypto.Cipher import AES
block_size = 16

def pad(data):
    padLength = block_size - (len(data) % block_size)
    return data + bytes([padLength]) * padLength

def unpad(data):
    return data[:-data[-1]]



key = b"midsem is coming"
cipher = AES.new(key, AES.MODE_ECB)





def encryptblocks(paddedPT):
    blocks = []
    for i in range(0, len(paddedPT), block_size):
        blocks.append(paddedPT[i:i+block_size])

    cblocks = []
    for b in blocks:
        cblocks.append(cipher.encrypt(b))

    return b"".join(cblocks)

def decryptblocks(ciphertext):
    blocks = []
    for i in range(0, len(ciphertext), block_size):
        blocks.append(ciphertext[i:i+block_size])

    pblocks = []
    for b in blocks:
        pblocks.append(cipher.decrypt(b))

    return unpad(b"".join(pblocks))






print("\n 1st original victim message  ")

pt_victim = (
    b"user=rahul______"
    b"role=user_______"
    b"valid=yes_______"
)

print("plaintext:", pt_victim)

ct_victim = encryptblocks(pad(pt_victim))





print("\n 2nd  attacker observes another ciphertext  ")

pt_admin = (
    b"user=admin______"
    b"role=admin______"
    b"valid=yes_______"
)

ct_admin = encryptblocks(pad(pt_admin))






print("\n 3rd attacker cuts and pastes blocks  ")

# split victim ciphertext
victim_blocks = []
for i in range(0, len(ct_victim), block_size):
    victim_blocks.append(ct_victim[i:i+block_size])

# split admin ciphertext
admin_blocks = []
for i in range(0, len(ct_admin), block_size):
    admin_blocks.append(ct_admin[i:i+block_size])

# replace role=user block with role=admin block
victim_blocks[1] = admin_blocks[1]

tampered_ciphertext = b"".join(victim_blocks)



print("\n 4th victim decrypts  ")

tampered_plaintext = decryptblocks(tampered_ciphertext)
print("tampered plaintext:", tampered_plaintext)

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = b"midsem is coming"
iv  = b"start  preparing"
block_size = 16

# encryption function 
def encrypt(pt):

    # split plaintext into blocks
    blocks = []
    for i in range(0, len(pt), block_size):
        blocks.append(pt[i:i+block_size])

    prev = iv
    cblocks = []

    for b in blocks:

        cipher = AES.new(key, AES.MODE_ECB)
        ofb_block = cipher.encrypt(prev)   

        # XOR plaintext block with keystream
        c = bytes([b[i] ^ ofb_block[i] for i in range(len(b))])

        cblocks.append(c)

        prev = ofb_block   

    return b"".join(cblocks)



# decryption function 
def decrypt(ct):

    # split ciphertext into blocks
    blocks = []
    for i in range(0, len(ct), block_size):
        blocks.append(ct[i:i+block_size])

    prev = iv
    pblocks = []

    for b in blocks:

        cipher = AES.new(key, AES.MODE_ECB)
        ofb_block = cipher.encrypt(prev)   

        # XOR ciphertext block with keystream
        p = bytes([b[i] ^ ofb_block[i] for i in range(len(b))])

        pblocks.append(p)

        prev = ofb_block   

    return b"".join(pblocks)





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

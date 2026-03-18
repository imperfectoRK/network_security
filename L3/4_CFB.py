from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

block_size = 16

key = b"midsem is coming"
iv  = b"start  preparing"# size 16



# encryption function 
def encrypt(pt):

    blocks = []
    for i in range(0, len(pt), block_size):
        blocks.append(pt[i:i+block_size])

    prev = iv
    cblocks = []

    for b in blocks:

        cipher = AES.new(key, AES.MODE_ECB)
        keystream = cipher.encrypt(prev)

        # XOR plaintext with keystream
        c = bytes([b[i] ^ keystream[i] for i in range(len(b))])

        cblocks.append(c)

        prev = c   

    return b"".join(cblocks)



# decryption function 
def decrypt(ct):

    blocks = []
    for i in range(0, len(ct), block_size):
        blocks.append(ct[i:i+block_size])

    prev = iv
    pblocks = []

    for b in blocks:

        cipher = AES.new(key, AES.MODE_ECB)
        keystream = cipher.encrypt(prev)

        # XOR ciphertext with keystream
        p = bytes([b[i] ^ keystream[i] for i in range(len(b))])

        pblocks.append(p)

        prev = b   

    return b"".join(pblocks)




print("\n  cfb pattern test  ")

test_pt = b"a" * 32
ct = encrypt(test_pt)

print(ct[:16])
print(ct[16:32])


print("\n1st original message  ")

pt = b"user=rahul;plan=basic;quota=100;abcdefghihjklmno_COMEBACK" #16( a to o)
ct = encrypt(pt)

print("plaintext:", pt)


print("\n 2nd  attacker flips bits  ")

ct_mod = bytearray(ct)

# change quota=100 -> quota=900


# '1' -> '9'
idx = pt.index(b"100")
original = ord('1')      
desired  = ord('9')      
XOR_value = ord('1') ^ ord('9')
ct_mod[idx] ^= XOR_value

modifiedCT = bytes(ct_mod)


print("\n 3rd victim decrypts  ")

modifiedPT = decrypt(modifiedCT)
print("modified plaintext:", modifiedPT)

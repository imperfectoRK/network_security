from Crypto.Cipher import AES
block_size = 16

def pad(data):
    padLength = block_size - (len(data) % block_size)
    return data + bytes([padLength]) * padLength

def unpad(data):
    return data[:-data[-1]]



key = b"midsem is coming"

cipher = AES.new(key, AES.MODE_ECB)




# encrytion funtion
def encryptfun(paddedPT):
    blocks = []
    for i in range(0, len(paddedPT), block_size):
        blocks.append(paddedPT[i:i+block_size])

    cblocks = []
    for b in blocks:
        cblocks.append(cipher.encrypt(b))

    return b"".join(cblocks)



# decryption function
def decryptfun(ciphertext):
    blocks = []
    for i in range(0, len(ciphertext), block_size):
        blocks.append(ciphertext[i:i+block_size])

    pblocks = []
    for b in blocks:
        pblocks.append(cipher.decrypt(b))

    return unpad(b"".join(pblocks))






print("\n 1st original message  ")
senderPT = (b"user=rahul______"b"role=user_______"b"valid=yes_______")
print("plaintext:", senderPT)

senderCT = encryptfun(pad(senderPT))





print("\n 2nd  observed another ciphertext  ")

adminPT = (b"user=admin______"b"role=admin______"b"valid=yes_______")
print(adminPT)
adminCT = encryptfun(pad(adminPT))






print("\n 3rd attacker cuts and pastes blocks  ")
print("replacing role=user with ==> role=admin block")
# split sender ciphertext
sender_blocks = []

for i in range(0, len(senderCT), block_size):
    sender_blocks.append(senderCT[i:i+block_size])



# split admin ciphertext
admin_blocks = []
for i in range(0, len(adminCT), block_size):
    admin_blocks.append(adminCT[i:i+block_size])




# replacing role=user with ==> role=admin block

sender_blocks[1] = admin_blocks[1]
CTdash = b"".join(sender_blocks)



print("\n 4th reciever decrypts  ")

PTdash = decryptfun(CTdash)
print("modified plaintext:", PTdash)

from Crypto.Cipher import AES
block_size = 16

def pad(data):
     padLength=block_size-(len(data)%block_size) 
     padding=bytes([padLength])*padLength 
     return data+padding 

def unpad(data):
     padlength=data[-1] 
     return data[:-padlength]



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



print("\n ECB pattern test ")

test_pt = b"A" * 32        # two identical blocks
test_padded = pad(test_pt)

ct = encryptfun(test_padded)

print(ct[:16])
print(ct[16:32])   # TRUE (same blocks in ECB)





print("\n 1st original message  ")
senderPT = (b"user=rahul______"b"role=user_______"b"valid=yes_______")
print("plaintext:", senderPT)

senderCT = encryptfun(pad(senderPT))





print("\n 2nd  observed another ciphertext  ")

adminPT = (b"user=admin______"b"role=admin______"b"valid=yes_______")
print(adminPT)
adminCT = encryptfun(pad(adminPT))






print("\n 3rd cuts and pastes blocks  ")
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

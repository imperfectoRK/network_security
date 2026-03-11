# Lab 3
## Block Cipher Modes Vulnerabilities
**Rahul Kumar**

---

## 1. Electronic Codebook Mode

In ECB mode, every block of plaintext is encrypted separately using the same key. If two blocks of plaintext are the same, the resulting ciphertext blocks will also be identical.

**The Attack:** Because blocks are independent, we can swap one block for another without needing the key. In the code, in this taken the "admin" role block from one message and pastes it into a "user" message.

### Code

Initially a padding function is used to make the plaintext a multiple of the AES block size (16 bytes). Then the program encrypts plaintext messages by splitting them into blocks and encrypting each block using AES in ECB mode. Two messages are encrypted: one for a normal user and another for an admin. An attacker then copies the ciphertext block containing `role=admin` from the admin message and replaces the `role=user` block in the user's ciphertext. When the modified ciphertext is decrypted, the receiver obtains a message where the role becomes admin, demonstrating the weakness of ECB mode.

**For encryption:**
$$C_i = E_k(P_i)$$

**For decryption:**
$$P_i = D_k(C_i)$$

**Result:** The decrypted message shows admin privileges for user role.

---

## 2. Cipher Block Chaining Mode

CBC mode links blocks together. Each block of plaintext is XORed with the previous ciphertext block before being encrypted. This mode uses an Initialization Vector (IV) so that identical plaintexts result in different ciphertexts.

**The Attack (Bit-Flipping):** If we change a byte in ciphertext block $C_i$, it directly changes the same byte in the decrypted plaintext block $P_{i+1}$, but $P_i$ becomes garbage.

### Code

Initially defined padding and unpadding functions so the plaintext length becomes a multiple of the AES block size (16 bytes). Then a key and (IV) are used to encrypt and decrypt data using AES in CBC mode. A message containing `Amount=1000` is encrypted. The attacker then modifies one byte in the ciphertext by applying an XOR operation so that the character `1` changes to `9`. When the modified ciphertext is decrypted by the receiver, the plaintext becomes `Amount=9000`, showing how bit flipping in CBC mode can alter the decrypted message without knowing the key.

**For encryption:**
$$C_0 = E_k(IV \oplus P_0) \quad \text{then} \quad C_i = E_k(C_{i-1} \oplus P_i)$$

**For decryption:**
$$P_0 = D_k(C_0) \oplus IV \quad \text{then} \quad P_i = D_k(C_i) \oplus C_{i-1}$$

**Result:** By flipping specific bits in the ciphertext, we successfully changed `amount=1000` to `amount=9000`.

---

## 3. Output Feedback (OFB) Mode

OFB mode turns a block cipher into a stream cipher. It encrypts the IV repeatedly to create a keystream which is then XORed with the plaintext. The plaintext itself is never put through the AES algorithm; it is only XORed with the keystream.

**The Attack (Bit-Flipping):** Since it works like a stream cipher, changing one bit in the ciphertext changes the exact same bit in the decrypted plaintext.

### Code

Initially a key and (IV) are defined and used to encrypt and decrypt data using AES in OFB mode. A test is performed to show that OFB does not produce repeating ciphertext patterns for identical plaintext blocks. Then a message containing `token=100` is encrypted. An attacker modifies the ciphertext by flipping specific bits using an XOR operation to change the value from `100` to `900`. When the modified ciphertext is decrypted, the receiver gets the altered plaintext, showing how OFB mode allows controlled modification of decrypted data without knowing the encryption key.

**For encryption:**
$$C_i = S_i \oplus P_i \quad \text{where} \quad S_0 = E_k(IV), \quad S_i = E_k(S_{i-1})$$

**For decryption:**
$$P_0 = D_k(S_0) \oplus C_i \quad \text{then} \quad P_i = D_k(S_i) \oplus C_i$$

**Result:** We changed `1` to `9` in the quota field by XORing the ciphertext at the correct position.

---

## 4. Cipher Feedback Mode

CFB is similar to CBC but also acts like a stream cipher. It encrypts the previous ciphertext block to produce the next keystream. Like OFB, it is highly sensitive to bit-level manipulation.

**The Attack (Bit-Flipping):** If we identify the index of the data we want to change, by XORing the ciphertext with the difference between the old character and the new character, the change appears after decryption.

### Code

Initially a key and (IV) are defined and used to encrypt and decrypt plaintext using AES in CFB mode. A test is performed to show the ciphertext pattern when encrypting repeated characters. Then a message containing `quota=100` is encrypted. An attacker modifies the ciphertext by flipping specific bits using an XOR operation so that the value `100` changes to `900`. When the modified ciphertext is decrypted by the receiver, the plaintext is altered, demonstrating how bit-flipping in CFB mode can change the decrypted message without knowing the secret key.

**For encryption:**
$$C_i = S_i \oplus P_i \quad \text{where} \quad S_0 = E_k(IV), \quad S_i = E_k(C_{i-1})$$

**For decryption:**
$$P_0 = D_k(S_0) \oplus C_i \quad \text{then} \quad P_i = D_k(C_{i-1}) \oplus C_i$$

**Result:** The `quota=100` was successfully changed to `quota=900`.

---

## 5. Counter Mode

CTR mode encrypts an incrementing counter to create a keystream. It is widely used because it is fast and can be done in parallel. It is a pure stream cipher implementation.

**The Attack (Malleability):** CTR mode is "malleable." This means an attacker can precisely modify the plaintext if they know what the original message was or a specific block.

### Code

First, a key and a random nonce are generated and used to encrypt and decrypt data using AES in CTR mode. A test is performed to observe the ciphertext blocks when encrypting repeated plaintext. Then a message containing `role=user` and `cmd=view` is encrypted. An attacker modifies specific bytes of the ciphertext using XOR operations to change `role=user` to `role=root` and `cmd=view` to `cmd=kill`. When the modified ciphertext is decrypted, the plaintext reflects these changes, showing that in CTR mode attackers can alter decrypted data without knowing the encryption key.

**For encryption:**
$$C_i = P_i \oplus E_k(\text{counter}_i)$$

**For decryption:**
$$P_i = C_i \oplus E_k(\text{counter}_i)$$

**Result:** We changed `role=user` to `role=root` and `cmd=view` to `cmd=kill`. This shows that CTR mode provides privacy but no integrity.

# Appendix B: shows that ECB mode gives identical ciphertext for identical plaintext blocks.
# It uses the same DES implementation (my_des.py) and the same key as the client and server.
 
from my_des import des_ecb_encrypt, pad
 
key = b"12345678"
message = b"TRANSFERTRANSFER"      # two identical 8-byte blocks: "TRANSFER" + "TRANSFER"
#message = b"123456781234567" 
 
padded = pad(message, 8)            # what actually gets encrypted (adds one padding block)
ciphertext = des_ecb_encrypt(message, key)
 
print("Plaintext message:", message.decode())
print("Full ciphertext (hex):", ciphertext.hex())
print()
 
# Show every 8-byte block next to its ciphertext block
for i in range(0, len(padded), 8):
    plain_block = padded[i:i + 8]
    cipher_block = ciphertext[i:i + 8]
    if plain_block.isascii() and plain_block.decode().isprintable():
        label = plain_block.decode()
    else:
        label = "(PKCS#7 padding)"
    print(f"Block {i // 8 + 1}: {label:<17} -> {cipher_block.hex()}")
 
print()
print("Ciphertext block 1 == block 2:", ciphertext[0:8] == ciphertext[8:16])
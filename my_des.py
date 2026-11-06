# my_des.py
# DES (Data Encryption Standard) implemented from scratch in ECB mode.
# No external libraries are used. The tables below are the standard DES tables
# from FIPS PUB 46. Positions are numbered from 1, as in the standard.
 
IP = [58,50,42,34,26,18,10,2,
      60,52,44,36,28,20,12,4,
      62,54,46,38,30,22,14,6,
      64,56,48,40,32,24,16,8,
      57,49,41,33,25,17,9,1,
      59,51,43,35,27,19,11,3,
      61,53,45,37,29,21,13,5,
      63,55,47,39,31,23,15,7]
 
FP = [40,8,48,16,56,24,64,32,
      39,7,47,15,55,23,63,31,
      38,6,46,14,54,22,62,30,
      37,5,45,13,53,21,61,29,
      36,4,44,12,52,20,60,28,
      35,3,43,11,51,19,59,27,
      34,2,42,10,50,18,58,26,
      33,1,41,9,49,17,57,25]
 
E = [32,1,2,3,4,5,
     4,5,6,7,8,9,
     8,9,10,11,12,13,
     12,13,14,15,16,17,
     16,17,18,19,20,21,
     20,21,22,23,24,25,
     24,25,26,27,28,29,
     28,29,30,31,32,1]
 
P = [16,7,20,21,29,12,28,17,
     1,15,23,26,5,18,31,10,
     2,8,24,14,32,27,3,9,
     19,13,30,6,22,11,4,25]
 
PC1 = [57,49,41,33,25,17,9,
       1,58,50,42,34,26,18,
       10,2,59,51,43,35,27,
       19,11,3,60,52,44,36,
       63,55,47,39,31,23,15,
       7,62,54,46,38,30,22,
       14,6,61,53,45,37,29,
       21,13,5,28,20,12,4]
 
PC2 = [14,17,11,24,1,5,
       3,28,15,6,21,10,
       23,19,12,4,26,8,
       16,7,27,20,13,2,
       41,52,31,37,47,55,
       30,40,51,45,33,48,
       44,49,39,56,34,53,
       46,42,50,36,29,32]
 
SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
 
# S_BOXES[i] is a list of 4 rows (0-3), each with 16 columns (0-15).
S_BOXES = [
 [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
  [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
  [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
  [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
 [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
  [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
  [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
  [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
 [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
  [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
  [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
  [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
 [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
  [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
  [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
  [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
 [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
  [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
  [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
  [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
 [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
  [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
  [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
  [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
 [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
  [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
  [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
  [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
 [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
  [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
  [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
  [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]
 
 
# ---------- Small helper functions ----------
 
def bytes_to_bits(data):
    """Turn bytes into a list of bits, e.g. b'A' -> [0,1,0,0,0,0,0,1]."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits
 
 
def bits_to_bytes(bits):
    """Turn a list of bits back into bytes."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | bit
        result.append(value)
    return bytes(result)
 
 
def permute(bits, table):
    """Rearrange bits using a DES table (table entries start at 1)."""
    return [bits[position - 1] for position in table]
 
 
def xor(a, b):
    """XOR two lists of bits."""
    return [x ^ y for x, y in zip(a, b)]
 
 
def rotate_left(bits, n):
    """Circular left shift of a list of bits."""
    return bits[n:] + bits[:n]
 
 
# ---------- DES steps ----------
 
def make_subkeys(key):
    """Key schedule: turn the 64-bit key into sixteen 48-bit round keys."""
    key_bits = bytes_to_bits(key)
    key56 = permute(key_bits, PC1)            # drop the 8 parity bits
    left, right = key56[:28], key56[28:]
    subkeys = []
    for shift in SHIFTS:                      # one round key per round
        left = rotate_left(left, shift)
        right = rotate_left(right, shift)
        subkeys.append(permute(left + right, PC2))
    return subkeys
 
 
def round_function(right, subkey):
    """The DES function f: expand, XOR with key, S-boxes, P-box."""
    expanded = permute(right, E)              # 32 bits -> 48 bits
    mixed = xor(expanded, subkey)             # key mixing
    output = []
    for i in range(8):                        # eight S-boxes
        group = mixed[i * 6:(i + 1) * 6]      # 6 bits go in
        row = group[0] * 2 + group[5]         # outer bits -> row
        col = group[1] * 8 + group[2] * 4 + group[3] * 2 + group[4]  # middle 4 -> column
        value = S_BOXES[i][row][col]          # 4 bits come out
        output += [(value >> 3) & 1, (value >> 2) & 1, (value >> 1) & 1, value & 1]
    return permute(output, P)                 # P-box permutation
 
 
def des_block(block, subkeys):
    """Encrypt (or decrypt) one 8-byte block. Pass the subkeys reversed to decrypt."""
    bits = permute(bytes_to_bits(block), IP)  # initial permutation
    left, right = bits[:32], bits[32:]
    for subkey in subkeys:                    # 16 Feistel rounds
        left, right = right, xor(left, round_function(right, subkey))
    combined = right + left                   # final swap of the halves
    return bits_to_bytes(permute(combined, FP))   # inverse initial permutation
 
 
# ---------- Padding (PKCS#7) ----------
 
def pad(data, block_size=8):
    """Add PKCS#7 padding. A full extra block is added if the length is already a multiple."""
    pad_length = block_size - (len(data) % block_size)
    return data + bytes([pad_length]) * pad_length
 
 
def unpad(data, block_size=8):
    """Remove PKCS#7 padding and check that it is valid."""
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_length = data[-1]
    if pad_length < 1 or pad_length > block_size or data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("Invalid padding")
    return data[:-pad_length]
 
 
# ---------- ECB mode ----------
 
def des_ecb_encrypt(plaintext, key):
    """Pad the message, then encrypt every 8-byte block independently with the same key."""
    subkeys = make_subkeys(key)
    padded = pad(plaintext, 8)
    ciphertext = b""
    for i in range(0, len(padded), 8):
        ciphertext += des_block(padded[i:i + 8], subkeys)
    return ciphertext
 
 
def des_ecb_decrypt(ciphertext, key):
    """Decrypt every 8-byte block with the round keys in reverse order, then remove padding."""
    subkeys = make_subkeys(key)[::-1]
    padded = b""
    for i in range(0, len(ciphertext), 8):
        padded += des_block(ciphertext[i:i + 8], subkeys)
    return unpad(padded, 8)
 
 
# ---------- Self-test (runs only if you run this file directly) ----------
    """
if __name__ == "__main__":
    # A well-known DES test vector: key 133457799BBCDFF1, plaintext 0123456789ABCDEF
    test_key = bytes.fromhex("133457799BBCDFF1")
    test_block = bytes.fromhex("0123456789ABCDEF")
    result = des_block(test_block, make_subkeys(test_key))
    print("Test vector result:", result.hex().upper(), "(expected 85E813540F0AB405)") 
 """
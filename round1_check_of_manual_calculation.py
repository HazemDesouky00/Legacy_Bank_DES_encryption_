# round1_check.py
# Prints every value of DES round 1 using the tables and functions in my_des.py,
# so the hand calculation in Appendix A can be checked against the program.

from my_des import (IP, PC1, PC2, E, P, S_BOXES, bytes_to_bits, bits_to_bytes,
                    permute, xor, rotate_left)

plaintext = b"HAZEM123"
key = b"12345678"

def show(bits, size):
    """Print bits in groups, e.g. size 8 -> bytes, size 4 -> nibbles."""
    text = "".join(str(b) for b in bits)
    return " ".join(text[i:i + size] for i in range(0, len(text), size))

print("Step 1  P (64):      ", show(bytes_to_bits(plaintext), 8))

ip = permute(bytes_to_bits(plaintext), IP)
L0, R0 = ip[:32], ip[32:]
print("Step 2  IP output:   ", show(ip, 8))
print("        L0:          ", show(L0, 4))
print("        R0:          ", show(R0, 4))

key_bits = bytes_to_bits(key)
print("Step 3  K (64):      ", show(key_bits, 8))

key56 = permute(key_bits, PC1)
C0, D0 = key56[:28], key56[28:]
C1, D1 = rotate_left(C0, 1), rotate_left(D0, 1)
K1 = permute(C1 + D1, PC2)
print("Step 4  PC-1 (56):   ", show(key56, 7))
print("        C0:          ", show(C0, 7))
print("        D0:          ", show(D0, 7))
print("        C1:          ", show(C1, 7))
print("        D1:          ", show(D1, 7))
print("        K1 (48):     ", show(K1, 6))

expanded = permute(R0, E)
print("Step 5  E(R0) (48):  ", show(expanded, 6))

mixed = xor(expanded, K1)
print("Step 6  XOR with K1: ", show(mixed, 6))

print("Step 7  S-boxes:")
sbox_out = []
for i in range(8):
    group = mixed[i * 6:(i + 1) * 6]
    row = group[0] * 2 + group[5]
    col = group[1] * 8 + group[2] * 4 + group[3] * 2 + group[4]
    value = S_BOXES[i][row][col]
    bits4 = [(value >> 3) & 1, (value >> 2) & 1, (value >> 1) & 1, value & 1]
    sbox_out += bits4
    print(f"        S{i + 1}: input {show(group, 6)}  row {row}  column {col:2}  value {value:2}  output {show(bits4, 4)}")
print("        Combined:    ", show(sbox_out, 4))

f = permute(sbox_out, P)
print("Step 8  f(R0, K1):   ", show(f, 4))

L1 = R0
R1 = xor(L0, f)
print("Step 9  L1 = R0:     ", show(L1, 4))
print("        R1 = L0 XOR f:", show(R1, 4))

print("Step 10 Output after round 1 (hex):", bits_to_bytes(L1 + R1).hex().upper())
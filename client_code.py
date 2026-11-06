import socket
from my_des import des_ecb_encrypt
 
# The same 8-byte (64-bit) key is used by both programs.
key = b"12345678"
 
# Ask the user to type the transaction message (it cannot be empty).
message = input("Enter the transaction message: ")
while message.strip() == "":
    message = input("The message cannot be empty. Enter the transaction message: ")
 
# Encrypt using our own DES implementation in ECB mode (padding is added inside).
encrypted_message = des_ecb_encrypt(message.encode("utf-8"), key)
 
print("Original message:", message)
print("Encrypted ciphertext (hex):", encrypted_message.hex())
 
# Send only the encrypted bytes to the server over TCP/IP.
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("127.0.0.1", 5000))
client.sendall(encrypted_message)
client.close()
 
print("Encrypted message sent to server.")
 
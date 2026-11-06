import socket
from my_des import des_ecb_decrypt
 
# The same 8-byte (64-bit) key is used by both programs.
key = b"12345678"
 
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("127.0.0.1", 5000))
server.listen(1)
 
print("Server is waiting for the client...")
connection, address = server.accept()
print("Client connected:", address)
 
# Receive all encrypted bytes until the client finishes sending.
encrypted_message = b""
while True:
    data = connection.recv(1024)
    if not data:
        break
    encrypted_message += data
 
# Decrypt the message using our own DES implementation in ECB mode.
message = des_ecb_decrypt(encrypted_message, key).decode("utf-8")
 
print("Received ciphertext (hex):", encrypted_message.hex())
print("Decrypted transaction:", message)
 
connection.close()
server.close()
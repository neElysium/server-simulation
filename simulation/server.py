import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

import hashlib
import secrets

# create 128 bit key

def generate_random_shared_secret():
    # Generate a random byte string with 16 bytes (128 bits)
    shared_secret = secrets.token_bytes(16)
    return shared_secret

# Server side functions
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def generate_hash(data):
    sha1 = hashlib.sha1()
    sha1.update(data)
    return sha1.digest()

def server_handshake(conn):
    private_key = generate_rsa_keypair()
    public_key = private_key.public_key()
    print("Server's private and public key generated:", private_key, "\n", public_key)
    print("Serialized_public_key:", serialize_public_key(public_key))
    client_public_key = serialization.load_pem_public_key(
        conn.recv(4096),
        backend=default_backend()
    )
    print("Client public key:", serialize_public_key(client_public_key))

    conn.sendall(serialize_public_key(public_key))

    secret_key = generate_random_shared_secret()
    print("secret_key:", secret_key)

    shared_key = client_public_key.encrypt(
        secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("shared_key:", shared_key)
    conn.sendall(shared_key)

    return secret_key

def server_receive(conn, sym_key):
    encrypted_data = conn.recv(4096)

    try:
        #decrypt the data using symmetric key
        decryptor = Cipher(algorithms.AES128(sym_key), modes.ECB(), backend=default_backend()).decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return decrypted_data
    
    except ValueError as e:
        return None


# Server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)

print("Server listening on port 12345")

conn, addr = server_socket.accept()
print(f"Connection established with {addr}")

symmetric_key = server_handshake(conn)

print("\n\nSymmetric key:", symmetric_key)

while True:
    data = server_receive(conn, symmetric_key)
    if not data:
        break
    print(f"Received data from client: {data.decode('utf-8')}")

conn.close()
print("Connection closed")


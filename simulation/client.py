from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import hashlib
import socket

# Client side functions

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


def client_handshake(conn):
    private_key = generate_rsa_keypair()
    public_key = private_key.public_key()
    print("Client's private and public key generated:", private_key, "\n", public_key)
    print("Serialized_public_key:", serialize_public_key(public_key))
    conn.sendall(serialize_public_key(public_key))
    
    server_public_key = serialization.load_pem_public_key(
        conn.recv(4096),
        backend=default_backend()
    )
    print("Server public key:", serialize_public_key(server_public_key))

    # Receive the encrypted shared secret
    shared_key = conn.recv(4096)
    print("shared_key:",shared_key)

    secret_key = private_key.decrypt(
        shared_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("secret_key:", secret_key)
    # conn.sendall(serialize_public_key(public_key))
    return secret_key

def client_send(conn, sym_key, data):
     # Pad the data to a multiple of the block size
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encryptor = Cipher(algorithms.AES128(sym_key), modes.ECB(), backend=default_backend()).encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    conn.sendall(encrypted_data)

# Client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

print("Connected with server")

symmetric_key = client_handshake(client_socket)

print("\n\nSymmetric key received:", symmetric_key)

while True:
    message = input("Enter a message to send to the server (or type 'exit' to quit): ")
    if message.lower() == 'exit':
        break
    client_send(client_socket, symmetric_key, message.encode('utf-8'))

client_socket.close()
print("Connection closed")

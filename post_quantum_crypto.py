import numpy as np
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'post-quantum key agreement'
    ).derive(shared_secret)
    return derived_key

def encrypt_message(message, key):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from os import urandom
    
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(encrypted_message, key):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode()

# Simulating key exchange
private_key_A, public_key_A = generate_keys()
private_key_B, public_key_B = generate_keys()

shared_key_A = derive_shared_secret(private_key_A, public_key_B)
shared_key_B = derive_shared_secret(private_key_B, public_key_A)

assert shared_key_A == shared_key_B

message = "Post-quantum security is essential!"
encrypted_msg = encrypt_message(message, shared_key_A)
decrypted_msg = decrypt_message(encrypted_msg, shared_key_B)

print(f"Original message: {message}")
print(f"Decrypted message: {decrypted_msg}")


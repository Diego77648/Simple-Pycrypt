import os
import hashlib
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes
)

def encrypt_message(key, message):
    message = message.encode()
    nonce = os.urandom(12)
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message) + encryptor.finalize()
    return nonce + encrypted_message

def decrypt_message(key, encrypted_message):
    nonce, encrypted_message = encrypted_message[:12], encrypted_message[12:]
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    message = decryptor.update(encrypted_message) + decryptor.finalize()
    return message.decode()

def generate_key(password):
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        100000
    )
    return salt + key

password = "secret password"
key = generate_key(password)
message = "This is a secret message."
encrypted_message = encrypt_message(key[16:], message)
##decrypted_message = decrypt_message(key[16:], encrypted_message)

print("Original message:", message)
print("Encrypted message:", encrypted_message)
##print("Decrypted message:", decrypted_message)

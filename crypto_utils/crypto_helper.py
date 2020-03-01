import hashlib
import os

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Util.Padding import pad, unpad


def sign(message, rsa_key):
    if os.path.exists(rsa_key):
        with open(rsa_key, 'r') as f:
            content = f.read()
    else:
        content = rsa_key

    key = RSA.importKey(content)
    protocol = PKCS1_PSS.new(key)
    message_hash = SHA1.new(message)
    signature = protocol.sign(message_hash)
    return signature


def verify_signature(message, signature, rsa_key):
    if os.path.exists(rsa_key):
        with open(rsa_key, 'r') as f:
            content = f.read()
    else:
        content = rsa_key

    key = RSA.importKey(content)
    protocol = PKCS1_PSS.new(key)
    message_hash = SHA1.new(message)

    try:
        protocol.verify(message_hash, signature)
    except (ValueError, TypeError) as e:
        print(e)
        return False

    return True


def encrypt_rsa(plaintext, rsa_key):
    if os.path.exists(rsa_key):
        with open(rsa_key, 'r') as f:
            content = f.read()
    else:
        content = rsa_key

    key = RSA.importKey(content)
    protocol = PKCS1_OAEP.new(key)
    ciphertext = protocol.encrypt(plaintext)
    return ciphertext


def decrypt_rsa(ciphertext, rsa_key):
    if os.path.exists(rsa_key):
        with open(rsa_key, 'r') as f:
            content = f.read()
    else:
        content = rsa_key

    key = RSA.importKey(content)
    protocol = PKCS1_OAEP.new(key)
    plaintext = protocol.decrypt(ciphertext)
    return plaintext


def encrypt_aes_ecb(key, plaintext, mode, block_size):
    cipher = AES.new(key, mode)
    padded_text = pad(plaintext.encode(), block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return encrypted_text


def decrypt_aes_ecb(key, ciphertext, mode, block_size):
    cipher = AES.new(key, mode)
    unpadded_plaintext = unpad(cipher.decrypt(ciphertext), block_size)
    decoded_plaintext = unpadded_plaintext.decode('UTF-8')
    return decoded_plaintext


def encrypt_rsa_aes(message, aes_password, rsa_key):
    encoded_aes_password = aes_password.encode('UTF-8')
    key = hashlib.sha256(encoded_aes_password).digest()
    encrypted_message = encrypt_aes_ecb(key, message, AES.MODE_ECB, 32)
    encrypted_key = encrypt_rsa(key, rsa_key)
    return encrypted_message, encrypted_key


def decrypt_rsa_aes(encrypted_message, encrypted_password, rsa_key):
    aes_key = decrypt_rsa(encrypted_password, rsa_key)
    decrypted_message = decrypt_aes_ecb(aes_key, encrypted_message, AES.MODE_ECB, 32)
    return decrypted_message

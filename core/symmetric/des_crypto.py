from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generate_des_key() -> bytes:
    return get_random_bytes(8)  # DES uses 8 bytes = 64 bits (56 effective)


def encrypt_des(plaintext: bytes, key: bytes) -> dict:
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

    return {
        "algorithm": "DES",
        "ciphertext": ciphertext,
        "key": key,
        "iv": cipher.iv
    }


def decrypt_des(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)
    return plaintext
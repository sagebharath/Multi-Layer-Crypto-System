from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generate_aes_key(key_size_bits: int = 128) -> bytes:
    if key_size_bits == 128:
        return get_random_bytes(16)
    elif key_size_bits == 256:
        return get_random_bytes(32)
    else:
        raise ValueError("AES key size must be 128 or 256 bits")


def encrypt_aes(plaintext: bytes, key: bytes) -> dict:
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    return {
        "algorithm": "AES-128" if len(key) == 16 else "AES-256",
        "ciphertext": ciphertext,
        "key": key,
        "iv": cipher.iv
    }


def decrypt_aes(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa_keypair(bits: int = 2048) -> tuple[bytes, bytes]:
    """
    Returns (private_pem, public_pem)
    """
    key = RSA.generate(bits)
    private_pem = key.export_key()
    public_pem = key.publickey().export_key()
    return private_pem, public_pem


def rsa_wrap_key(key_bytes: bytes, public_pem: bytes) -> bytes:
    pub_key = RSA.import_key(public_pem)
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    return cipher_rsa.encrypt(key_bytes)


def rsa_unwrap_key(wrapped_key: bytes, private_pem: bytes) -> bytes:
    priv_key = RSA.import_key(private_pem)
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    return cipher_rsa.decrypt(wrapped_key)
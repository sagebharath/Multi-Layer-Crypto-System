from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
    load_pem_private_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def generate_ecc_keypair() -> tuple[bytes, bytes]:
    """
    Returns (private_pem, public_bytes_uncompressed_point)
    Curve: SECP256R1
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    public_bytes = public_key.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint
    )

    return private_pem, public_bytes


def _derive_kek(shared_secret: bytes, length: int = 32) -> bytes:
    """
    Derive a key-encryption-key (KEK) from ECDH shared secret using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b"multi-layer-crypto-ecc-keywrap",
    )
    return hkdf.derive(shared_secret)


def ecc_wrap_key(key_bytes: bytes, recipient_public_bytes: bytes) -> dict:
    """
    Returns dict:
      {
        "ephemeral_pub": bytes,
        "nonce": bytes,
        "ciphertext": bytes   # includes GCM tag
      }
    """
    recipient_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), recipient_public_bytes
    )

    eph_private = ec.generate_private_key(ec.SECP256R1())
    eph_public = eph_private.public_key()

    shared_secret = eph_private.exchange(ec.ECDH(), recipient_public_key)
    kek = _derive_kek(shared_secret, length=32)

    aesgcm = AESGCM(kek)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, key_bytes, associated_data=None)

    eph_pub_bytes = eph_public.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    return {"ephemeral_pub": eph_pub_bytes, "nonce": nonce, "ciphertext": ct}


def ecc_unwrap_key(wrapped: dict, recipient_private_pem: bytes) -> bytes:
    recipient_private = load_pem_private_key(recipient_private_pem, password=None)

    eph_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), wrapped["ephemeral_pub"]
    )

    shared_secret = recipient_private.exchange(ec.ECDH(), eph_public)
    kek = _derive_kek(shared_secret, length=32)

    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(wrapped["nonce"], wrapped["ciphertext"], associated_data=None)
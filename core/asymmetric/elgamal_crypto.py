from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse


def generate_elgamal_keypair(bits: int = 2048) -> tuple[dict, dict]:
    """
    Returns (private_key_dict, public_key_dict)
    Keys are stored as Python ints for easy session storage.

    public:  {p,g,y}
    private: {p,g,y,x}
    """
    key = ElGamal.generate(bits, get_random_bytes)

    pub = {"p": int(key.p), "g": int(key.g), "y": int(key.y)}
    priv = {"p": int(key.p), "g": int(key.g), "y": int(key.y), "x": int(key.x)}
    return priv, pub


def elgamal_wrap_key(key_bytes: bytes, public_key: dict) -> dict:
    """
    Returns dict: {"a": int, "b": int, "key_len": int}
    """
    p = public_key["p"]
    g = public_key["g"]
    y = public_key["y"]

    key_len = len(key_bytes)

    # Convert key bytes to integer message m (ensure m != 0)
    m = bytes_to_long(key_bytes) + 1  # makes m >= 1
    if not (1 <= m < p):
        raise ValueError("Message too large for ElGamal modulus. Use larger key size.")

    k = random.StrongRandom().randint(1, p - 2)
    a = pow(g, k, p)
    b = (pow(y, k, p) * m) % p

    return {"a": int(a), "b": int(b), "key_len": int(key_len)}


def elgamal_unwrap_key(wrapped: dict, private_key: dict) -> bytes:
    """
    wrapped: {"a": int, "b": int, "key_len": int}
    """
    p = private_key["p"]
    x = private_key["x"]

    a = wrapped["a"]
    b = wrapped["b"]
    key_len = wrapped["key_len"]

    s = pow(a, x, p)              # shared secret
    s_inv = inverse(s, p)         # multiplicative inverse mod p
    m = (b * s_inv) % p

    # Undo the +1 we added during wrap
    m = m - 1
    if m < 0:
        raise ValueError("ElGamal unwrap failed (invalid ciphertext).")

    return long_to_bytes(m, key_len)
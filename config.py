SUPPORTED_SYMMETRIC_ALGOS = ["DES", "AES-128", "AES-256"]
SUPPORTED_ASSYMMETRIC_ALGOS = ["RSA", "ElGamal", "ECC"]

MAX_DATA_LAYERS = 3

SECURITY_LEVELS = {
    "Weak" : (0, 39),
    "Moderate" : (40, 59),
    "Strong" : (60, 79),
    "Very Strong" : (80, 100),
}
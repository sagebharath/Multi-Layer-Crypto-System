ALGORITHM_BASE_SCORES = {
    "DES" : 20,
    "AES-128" : 85, 
    "AES-256" : 95,
    "RSA-1024" : 55,
    "RSA-2048" : 80,
    "ElGamal-1024" : 60,
    "ElGamal-1024" : 82,
    "ECC-256" : 92,
}

ALGORITHM_STATUS_SCORES = {
    "DES" : 10,
    "AES-128" : 95,
    "AES-256" : 95,
    "RSA" : 85,
    "ElGamal" : 80,
    "ECC" : 95,
}

CLASSIFICATION_THRESHOLDS = {
    "Weak" : (0, 39),
    "Moderate" : (40, 59),
    "Strong" : (60, 79),
    "Very Strong" : (80, 100),
}
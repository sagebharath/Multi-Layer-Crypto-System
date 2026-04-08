SYMMETRIC_BASE = {
    "DES": 20,
    "AES-128": 85,
    "AES-256": 95,
}

SYMMETRIC_STATUS = {
    "DES": 10,
    "AES-128": 95,
    "AES-256": 95,
}

KEY_PROTECTION_BASE = {
    None: 0,
    "RSA": 80,       # assume RSA-2048
    "ElGamal": 82,   # assume 2048-bit group
    "ECC": 92,       # assume P-256
}


def _key_score(algorithm: str) -> int:
    if algorithm == "DES":
        return 20
    if algorithm == "AES-128":
        return 75
    if algorithm == "AES-256":
        return 95
    return 0


def calculate_layer_score(algorithm: str) -> float:
    base = SYMMETRIC_BASE.get(algorithm, 0)
    status = SYMMETRIC_STATUS.get(algorithm, 0)
    kscore = _key_score(algorithm)
    return round((0.5 * base) + (0.3 * kscore) + (0.2 * status), 2)


def calculate_final_score(layers: list[dict], key_protection: str | None) -> float:
    if not layers:
        return 0.0

    sym_scores = [calculate_layer_score(l["algorithm"]) for l in layers]
    sym_avg = sum(sym_scores) / len(sym_scores)

    # Layer bonus
    layer_bonus = 0
    if len(layers) == 2:
        layer_bonus = 5
    elif len(layers) >= 3:
        layer_bonus = 8

    kp_score = KEY_PROTECTION_BASE.get(key_protection, 0)

    # Blend symmetric strength with key protection (hybrid)
    # If no key protection, kp_score = 0 and it won't help.
    final = (0.75 * sym_avg) + (0.25 * kp_score) + layer_bonus
    final = min(round(final, 2), 100.0)
    return final


def classify_score(score: float) -> str:
    if score < 40:
        return "Weak"
    if score < 60:
        return "Moderate"
    if score < 80:
        return "Strong"
    return "Very Strong"


def get_recommendation(score: float, layers: list[dict], key_protection: str | None) -> str:
    algos = [l["algorithm"] for l in layers]

    if "DES" in algos and all(a == "DES" for a in algos):
        return "DES is deprecated and weak. Replace with AES-256."

    if key_protection is None:
        if score < 80:
            return "Consider enabling key protection (RSA/ElGamal/ECC) to secure symmetric keys in transit/storage."
        return "Encryption is strong, but enabling RSA/ECC key protection would make it closer to real-world hybrid encryption."

    if key_protection == "RSA":
        return "Hybrid encryption enabled (RSA). Consider ECC for smaller keys and strong security."

    if key_protection == "ElGamal":
        return "Hybrid encryption enabled (ElGamal). Consider ECC for better efficiency."

    if key_protection == "ECC":
        return "Hybrid encryption enabled (ECC). This is a modern efficient choice."

    return "Configuration looks good."
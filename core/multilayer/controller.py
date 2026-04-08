from core.symmetric.aes_crypto import generate_aes_key, encrypt_aes, decrypt_aes
from core.symmetric.des_crypto import generate_des_key, encrypt_des, decrypt_des

from core.asymmetric.rsa_crypto import rsa_wrap_key, rsa_unwrap_key
from core.asymmetric.elgamal_crypto import elgamal_wrap_key, elgamal_unwrap_key
from core.asymmetric.ecc_crypto import ecc_wrap_key, ecc_unwrap_key


def _encrypt_symmetric(data: bytes, algorithm: str) -> dict:
    if algorithm == "DES":
        key = generate_des_key()
        out = encrypt_des(data, key)
        return out

    if algorithm == "AES-128":
        key = generate_aes_key(128)
        out = encrypt_aes(data, key)
        return out

    if algorithm == "AES-256":
        key = generate_aes_key(256)
        out = encrypt_aes(data, key)
        return out

    raise ValueError(f"Unsupported symmetric algorithm: {algorithm}")


def _decrypt_symmetric(ciphertext: bytes, algorithm: str, key: bytes, iv: bytes) -> bytes:
    if algorithm == "DES":
        return decrypt_des(ciphertext, key, iv)

    if algorithm in ("AES-128", "AES-256"):
        return decrypt_aes(ciphertext, key, iv)

    raise ValueError(f"Unsupported symmetric algorithm during decryption: {algorithm}")


def _wrap_key(key_bytes: bytes, key_protection: str, public_material):
    if key_protection == "RSA":
        return {"type": "RSA", "wrapped_key": rsa_wrap_key(key_bytes, public_material)}

    if key_protection == "ElGamal":
        wrapped = elgamal_wrap_key(key_bytes, public_material)
        return {"type": "ElGamal", **wrapped}  # a,b,key_len

    if key_protection == "ECC":
        wrapped = ecc_wrap_key(key_bytes, public_material)
        return {"type": "ECC", **wrapped}  # ephemeral_pub, nonce, ciphertext

    raise ValueError(f"Unsupported key protection algorithm: {key_protection}")


def _unwrap_key(key_protection_block: dict, private_material_by_type: dict) -> bytes:
    kp_type = key_protection_block["type"]

    if kp_type == "RSA":
        priv_pem = private_material_by_type["RSA"]
        return rsa_unwrap_key(key_protection_block["wrapped_key"], priv_pem)

    if kp_type == "ElGamal":
        priv = private_material_by_type["ElGamal"]
        wrapped = {
            "a": key_protection_block["a"],
            "b": key_protection_block["b"],
            "key_len": key_protection_block["key_len"],
        }
        return elgamal_unwrap_key(wrapped, priv)

    if kp_type == "ECC":
        priv_pem = private_material_by_type["ECC"]
        wrapped = {
            "ephemeral_pub": key_protection_block["ephemeral_pub"],
            "nonce": key_protection_block["nonce"],
            "ciphertext": key_protection_block["ciphertext"],
        }
        return ecc_unwrap_key(wrapped, priv_pem)

    raise ValueError(f"Unsupported key protection type in metadata: {kp_type}")


def encrypt_multilayer(
    plaintext: bytes,
    algorithm_layers: list[str],
    key_protection: str | None = None,
    key_protection_public=None,
) -> dict:
    """
    algorithm_layers: ["DES", "AES-256", ...]
    key_protection: None / "RSA" / "ElGamal" / "ECC"
    key_protection_public: depends on key_protection
        - RSA: public_pem bytes
        - ElGamal: public dict {p,g,y}
        - ECC: public bytes (uncompressed point)
    """
    current = plaintext
    layers = []

    for algo in algorithm_layers:
        out = _encrypt_symmetric(current, algo)

        layer = {
            "algorithm": out["algorithm"],
            "iv": out["iv"],
            "ciphertext": out["ciphertext"],
        }

        if key_protection is None:
            # demo mode (stores raw key)
            layer["key"] = out["key"]
            layer["key_protection"] = None
        else:
            layer["key_protection"] = _wrap_key(out["key"], key_protection, key_protection_public)

        layers.append(layer)
        current = out["ciphertext"]

    return {"final_ciphertext": current, "layers": layers, "key_protection": key_protection}


def decrypt_multilayer(
    final_ciphertext: bytes,
    layers_metadata: list[dict],
    private_material_by_type: dict | None = None,
) -> bytes:
    """
    private_material_by_type:
      if RSA used: {"RSA": private_pem}
      if ElGamal: {"ElGamal": private_dict}
      if ECC: {"ECC": private_pem}
    """
    current = final_ciphertext

    for layer in reversed(layers_metadata):
        algo = layer["algorithm"]
        iv = layer["iv"]

        if layer.get("key_protection") is None:
            key = layer["key"]
        else:
            if private_material_by_type is None:
                raise ValueError("Private key material not provided for key-protected decryption.")
            key = _unwrap_key(layer["key_protection"], private_material_by_type)

        current = _decrypt_symmetric(current, algo, key, iv)

    return current
# Multi-Layer Crypto System (Adaptive Cipher Strength Analysis)

A Streamlit-based cryptography project that supports **multi-layer encryption** of text using symmetric ciphers (DES/AES) and optional **hybrid key protection** using public-key cryptography (RSA/ElGamal/ECC). The system also provides a **security strength score**, classification, and recommendations based on the chosen configuration.

> Note: DES is included for educational/comparative purposes and is considered insecure by modern standards.

---

## Key Features

### 1) Multi-Layer Data Encryption (Symmetric)
Encrypt the message using 1–3 layers of:
- **DES**
- **AES-128**
- **AES-256**

Each layer takes the previous layer’s ciphertext as input (cascading encryption). Decryption is done in reverse order.

### 2) Hybrid Key Protection (Asymmetric Key Wrapping)
Optionally protect (wrap) the symmetric keys using:
- **RSA (OAEP)**
- **ElGamal**
- **ECC** (ECDH + HKDF + AES-GCM key wrap; ECIES-like approach)

This is the standard hybrid encryption approach used in real systems:  
**symmetric encryption for data** + **public-key cryptography for securing symmetric keys**.

### 3) Adaptive Cipher Strength Analysis
After encryption, the system computes:
- a **final score (0–100)**
- a **classification**: Weak / Moderate / Strong / Very Strong
- an automatic **recommendation** (e.g., replace DES with AES-256, enable ECC key protection, etc.)

---

## Supported Algorithms

### Symmetric (data encryption)
- DES (CBC mode)
- AES-128 (CBC mode)
- AES-256 (CBC mode)

### Asymmetric (key protection / wrapping)
- RSA-2048 with OAEP padding
- ElGamal (2048-bit group)
- ECC (SECP256R1 / P-256)

---

## Project Structure (High Level)

- `app.py`  
  Streamlit UI (input, configuration, results, decryption)

- `core/symmetric/`  
  Symmetric crypto implementations (DES, AES)

- `core/asymmetric/`  
  Key wrapping implementations (RSA, ElGamal, ECC)

- `core/multilayer/`  
  Multi-layer controller (encryption chain + reverse decryption)

- `core/analysis/`  
  Scoring + classification + recommendation logic

- `core/utils/`  
  Base64 and byte/string helper utilities

---

## How It Works (Workflow)

1. User enters a plaintext message.
2. User selects the number of encryption layers and chooses DES/AES per layer.
3. The system encrypts the message layer-by-layer (cascading).
4. For each layer, a symmetric key is generated.
5. If key protection is enabled, the symmetric key is wrapped using RSA/ElGamal/ECC.
6. The system generates a security score and recommendations.
7. On decryption:
   - wrapped keys are unwrapped using the private key (if enabled)
   - ciphertext is decrypted in reverse order to recover the plaintext

---

## Installation (Windows)

### 1) Create and activate virtual environment
```powershell
python -m venv venv
.\venv\Scripts\Activate

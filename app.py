import streamlit as st

from core.utils.encoding import bytes_to_b64, str_to_bytes, bytes_to_str
from core.multilayer.controller import encrypt_multilayer, decrypt_multilayer
from core.analysis.scoring import calculate_final_score, classify_score, get_recommendation

from core.asymmetric.rsa_crypto import generate_rsa_keypair
from core.asymmetric.elgamal_crypto import generate_elgamal_keypair
from core.asymmetric.ecc_crypto import generate_ecc_keypair


st.set_page_config(page_title="Multi-Layer Crypto System", layout="centered")
st.title("Multi-Layer Cryptographic System with Adaptive Cipher Strength Analysis")

st.write("Data is encrypted using **DES/AES layers**. Optional **RSA/ElGamal/ECC** protects the symmetric keys (hybrid encryption).")

plaintext = st.text_area("Enter your message")

layer_count = st.selectbox("Select number of symmetric data-encryption layers", [1, 2, 3])
sym_options = ["DES", "AES-128", "AES-256"]

selected_layers = []
for i in range(layer_count):
    selected_layers.append(
        st.selectbox(f"Layer {i+1} algorithm", sym_options, key=f"layer_{i}")
    )

key_protection = st.selectbox(
    "Key protection (wrap symmetric keys using public-key crypto)",
    ["None", "RSA", "ElGamal", "ECC"]
)
key_protection = None if key_protection == "None" else key_protection

colA, colB = st.columns(2)
with colA:
    regen_keys = st.button("Regenerate Public/Private Keys")
with colB:
    st.caption("Keys are stored in the Streamlit session for demo/decryption.")

# ---- Keypair management in session ----
def ensure_keys():
    if key_protection is None:
        return

    if regen_keys:
        # wipe old keys
        for k in ["rsa_priv", "rsa_pub", "elg_priv", "elg_pub", "ecc_priv", "ecc_pub"]:
            if k in st.session_state:
                del st.session_state[k]

    if key_protection == "RSA":
        if "rsa_priv" not in st.session_state:
            priv, pub = generate_rsa_keypair(2048)
            st.session_state["rsa_priv"] = priv
            st.session_state["rsa_pub"] = pub

    elif key_protection == "ElGamal":
        if "elg_priv" not in st.session_state:
            priv, pub = generate_elgamal_keypair(2048)
            st.session_state["elg_priv"] = priv
            st.session_state["elg_pub"] = pub

    elif key_protection == "ECC":
        if "ecc_priv" not in st.session_state:
            priv, pub = generate_ecc_keypair()
            st.session_state["ecc_priv"] = priv
            st.session_state["ecc_pub"] = pub


ensure_keys()

# show public key info (optional)
if key_protection == "RSA" and "rsa_pub" in st.session_state:
    st.subheader("RSA Public Key (PEM)")
    st.code(st.session_state["rsa_pub"].decode("utf-8", errors="ignore"))

if key_protection == "ElGamal" and "elg_pub" in st.session_state:
    st.subheader("ElGamal Public Parameters")
    st.json(st.session_state["elg_pub"])

if key_protection == "ECC" and "ecc_pub" in st.session_state:
    st.subheader("ECC Public Key (X9.62 uncompressed point, Base64)")
    st.code(bytes_to_b64(st.session_state["ecc_pub"]), language="text")


# ---- Encrypt ----
if st.button("Encrypt"):
    if not plaintext.strip():
        st.error("Please enter a message.")
    else:
        public_material = None
        if key_protection == "RSA":
            public_material = st.session_state["rsa_pub"]
        elif key_protection == "ElGamal":
            public_material = st.session_state["elg_pub"]
        elif key_protection == "ECC":
            public_material = st.session_state["ecc_pub"]

        encrypted = encrypt_multilayer(
            plaintext=str_to_bytes(plaintext),
            algorithm_layers=selected_layers,
            key_protection=key_protection,
            key_protection_public=public_material,
        )

        score = calculate_final_score(encrypted["layers"], encrypted["key_protection"])
        classification = classify_score(score)
        recommendation = get_recommendation(score, encrypted["layers"], encrypted["key_protection"])

        st.session_state["encrypted_pkg"] = encrypted
        st.session_state["score"] = score
        st.session_state["classification"] = classification
        st.session_state["recommendation"] = recommendation


# ---- Display + Decrypt ----
if "encrypted_pkg" in st.session_state:
    pkg = st.session_state["encrypted_pkg"]

    st.subheader("Final Ciphertext (Base64)")
    st.code(bytes_to_b64(pkg["final_ciphertext"]), language="text")

    st.subheader("Layers Used")
    for i, layer in enumerate(pkg["layers"], start=1):
        kp = layer.get("key_protection")
        kp_txt = "None" if kp is None else kp["type"]
        st.write(f"**Layer {i}:** {layer['algorithm']} | Key protection: **{kp_txt}**")

    st.subheader("Security Analysis")
    st.write(f"**Score:** {st.session_state['score']}/100")
    st.write(f"**Classification:** {st.session_state['classification']}")
    st.info(st.session_state["recommendation"])

    if st.button("Decrypt"):
        private_material = None
        if pkg["key_protection"] == "RSA":
            private_material = {"RSA": st.session_state["rsa_priv"]}
        elif pkg["key_protection"] == "ElGamal":
            private_material = {"ElGamal": st.session_state["elg_priv"]}
        elif pkg["key_protection"] == "ECC":
            private_material = {"ECC": st.session_state["ecc_priv"]}

        decrypted_bytes = decrypt_multilayer(
            final_ciphertext=pkg["final_ciphertext"],
            layers_metadata=pkg["layers"],
            private_material_by_type=private_material,
        )

        st.subheader("Decrypted Message")
        st.success(bytes_to_str(decrypted_bytes))
"""
Post-Quantum Cryptography (PQC) Encryption
=========================================

This file demonstrates PQC-based secure communication with
EXPLICIT SECURITY LEVELS (measured in bits).

We follow NIST PQC standards.

------------------------------------------------------------
Security Levels (NIST-defined, not key size)
------------------------------------------------------------

Security Level 1  → ~128-bit classical security
Security Level 3  → ~192-bit classical security
Security Level 5  → ~256-bit classical security

These levels represent the estimated computational effort
required to break the scheme, even with quantum computers.

------------------------------------------------------------
Algorithms Used
------------------------------------------------------------

Key Encapsulation (PQC, Quantum-Resistant):
- ML-KEM (Kyber)
  - Kyber512  → Level 1 (128-bit security)
  - Kyber768  → Level 3 (192-bit security)
  - Kyber1024 → Level 5 (256-bit security)

Symmetric Encryption:
- AES-GCM
  - AES-128-GCM → 128-bit security
  - AES-256-GCM → 256-bit security

Design Pattern:
PQC (Key Exchange) + Symmetric Encryption (Data)

------------------------------------------------------------
Why Hybrid Encryption?
------------------------------------------------------------
- PQC algorithms are slow and size-heavy
- Symmetric crypto is fast and efficient
- PQC is used ONLY to exchange keys
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# PQC KEMs (Kyber / ML-KEM)
# pip install pqcrypto
from pqcrypto.kem import kyber512, kyber768, kyber1024


# ------------------------------------------------------------
# Utility helpers
# ------------------------------------------------------------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64d(data: str) -> bytes:
    return base64.b64decode(data)


# ------------------------------------------------------------
# PQC Profiles (Explicit security bits)
# ------------------------------------------------------------

PQC_PROFILES = {
    "LEVEL_1_128_BIT": {
        "kem": kyber512,     # ~128-bit PQ security
        "aes_bits": 128,
    },
    "LEVEL_3_192_BIT": {
        "kem": kyber768,     # ~192-bit PQ security
        "aes_bits": 256,    # AES-256 still recommended
    },
    "LEVEL_5_256_BIT": {
        "kem": kyber1024,    # ~256-bit PQ security
        "aes_bits": 256,
    },
}


# ------------------------------------------------------------
# Key Generation (Receiver)
# ------------------------------------------------------------

def generate_pqc_keypair(profile_name: str):
    """
    Generates PQC keypair for a given security level.

    Example:
    - LEVEL_1_128_BIT
    - LEVEL_3_192_BIT
    - LEVEL_5_256_BIT
    """

    profile = PQC_PROFILES[profile_name]
    kem = profile["kem"]

    public_key, private_key = kem.generate_keypair()

    return {
        "profile": profile_name,
        "public_key": b64e(public_key),
        "private_key": b64e(private_key),
    }


# ------------------------------------------------------------
# Sender: Encrypt message
# ------------------------------------------------------------

def pqc_encrypt_message(
    plaintext: str,
    receiver_public_key_b64: str,
    profile_name: str,
) -> dict:
    """
    Encryption Process (Bit-Level Explanation):

    1. PQC KEM generates a shared secret
       - Security: 128 / 192 / 256 bits (depending on profile)

    2. Shared secret is converted into AES key
       - AES-128-GCM or AES-256-GCM

    3. AES-GCM encrypts the message
       - Confidentiality + Integrity
    """

    profile = PQC_PROFILES[profile_name]
    kem = profile["kem"]
    aes_bits = profile["aes_bits"]

    public_key = b64d(receiver_public_key_b64)

    # Step 1: PQC key encapsulation
    kem_ciphertext, shared_secret = kem.encrypt(public_key)

    # Step 2: Derive AES key
    if aes_bits == 128:
        aes_key = shared_secret[:16]  # 128 bits
    else:
        aes_key = shared_secret[:32]  # 256 bits

    # Step 3: Symmetric encryption
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    encrypted_message = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return {
        "profile": profile_name,
        "security_bits": aes_bits,
        "kem_ciphertext": b64e(kem_ciphertext),
        "nonce": b64e(nonce),
        "ciphertext": b64e(encrypted_message),
    }


# ------------------------------------------------------------
# Receiver: Decrypt message
# ------------------------------------------------------------

def pqc_decrypt_message(payload: dict, receiver_private_key_b64: str) -> str:
    """
    Decryption reverses the process:

    1. PQC decapsulation recovers shared secret
    2. AES-GCM decrypts ciphertext
    """

    profile = PQC_PROFILES[payload["profile"]]
    kem = profile["kem"]
    aes_bits = profile["aes_bits"]

    private_key = b64d(receiver_private_key_b64)

    kem_ciphertext = b64d(payload["kem_ciphertext"])
    nonce = b64d(payload["nonce"])
    ciphertext = b64d(payload["ciphertext"])

    # Step 1: PQC decapsulation
    shared_secret = kem.decrypt(kem_ciphertext, private_key)

    # Step 2: Derive AES key
    if aes_bits == 128:
        aes_key = shared_secret[:16]
    else:
        aes_key = shared_secret[:32]

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode()


# ------------------------------------------------------------
# Example Usage
# ------------------------------------------------------------

if __name__ == "__main__":
    print("🔐 Generating Level 5 (256-bit) PQC keys...")
    keys = generate_pqc_keypair("LEVEL_5_256_BIT")

    print("📤 Encrypting message with 256-bit security...")
    encrypted_payload = pqc_encrypt_message(
        "Quantum-safe communication with 256-bit security",
        keys["public_key"],
        "LEVEL_5_256_BIT",
    )

    print("📥 Decrypting message...")
    decrypted = pqc_decrypt_message(
        encrypted_payload,
        keys["private_key"],
    )

    print("✅ Decrypted message:", decrypted)

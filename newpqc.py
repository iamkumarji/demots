"""
Post-Quantum Cryptography (PQC) Hybrid Encryption Example
=========================================================

This file demonstrates a PQC-safe communication scheme using:

1. ML-KEM (Kyber) for key exchange (Post-Quantum Secure)
2. AES-256-GCM for message encryption (Fast + Authenticated)

Why Hybrid?
-----------
- PQC algorithms are expensive and not suited for large data.
- We use PQC only to securely exchange a symmetric key.
- AES then encrypts the actual message.

Security Properties
-------------------
✔ Quantum-resistant key exchange
✔ Confidentiality
✔ Integrity & authentication (via AES-GCM)
✔ Forward secrecy (if keys are ephemeral)

Compatible with:
- TLS 1.3 PQC hybrid concepts
- NIST PQC recommendations
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Kyber (ML-KEM) implementation
# pip install pqcrypto
from pqcrypto.kem.kyber768 import generate_keypair, encrypt, decrypt


# -------------------------------------------------
# Utilities
# -------------------------------------------------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()

def b64d(data: str) -> bytes:
    return base64.b64decode(data)


# -------------------------------------------------
# Key Generation (Receiver side)
# -------------------------------------------------

def generate_pqc_keypair():
    """
    Generates a post-quantum Kyber keypair.

    public_key  → shared with sender
    private_key → kept secret
    """
    public_key, private_key = generate_keypair()
    return b64e(public_key), b64e(private_key)


# -------------------------------------------------
# Sender: Encrypt message
# -------------------------------------------------

def pqc_encrypt_message(plaintext: str, receiver_public_key_b64: str) -> dict:
    """
    Sender encrypts a message using receiver's PQC public key.

    Steps:
    1. Encapsulate a shared secret using Kyber
    2. Use shared secret as AES-256-GCM key
    3. Encrypt the message
    """

    receiver_public_key = b64d(receiver_public_key_b64)

    # Step 1: PQC key encapsulation
    ciphertext, shared_secret = encrypt(receiver_public_key)

    # Step 2: AES-GCM encryption
    aes_key = shared_secret[:32]  # AES-256
    nonce = os.urandom(12)

    aesgcm = AESGCM(aes_key)
    encrypted_message = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return {
        "kem_ciphertext": b64e(ciphertext),
        "nonce": b64e(nonce),
        "ciphertext": b64e(encrypted_message),
    }


# -------------------------------------------------
# Receiver: Decrypt message
# -------------------------------------------------

def pqc_decrypt_message(payload: dict, receiver_private_key_b64: str) -> str:
    """
    Receiver decrypts message using private key.

    Steps:
    1. Recover shared secret via Kyber decapsulation
    2. Use shared secret to decrypt AES-GCM payload
    """

    private_key = b64d(receiver_private_key_b64)

    kem_ciphertext = b64d(payload["kem_ciphertext"])
    nonce = b64d(payload["nonce"])
    ciphertext = b64d(payload["ciphertext"])

    # Step 1: PQC decapsulation
    shared_secret = decrypt(kem_ciphertext, private_key)

    # Step 2: AES-GCM decryption
    aes_key = shared_secret[:32]
    aesgcm = AESGCM(aes_key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


# -------------------------------------------------
# Example Communication Flow
# -------------------------------------------------

if __name__ == "__main__":
    print("🔐 Generating PQC keypair for receiver...")
    public_key_b64, private_key_b64 = generate_pqc_keypair()

    print("📤 Sender encrypts message...")
    payload = pqc_encrypt_message(
        "Hello, this message is quantum-safe 🚀",
        public_key_b64,
    )

    print("📥 Receiver decrypts message...")
    message = pqc_decrypt_message(payload, private_key_b64)

    print("✅ Decrypted message:", message)

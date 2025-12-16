import os
import base64
from typing import List
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# -------------------------------------------------
# Environment helpers
# -------------------------------------------------

def get_env(key: str, default=None):
    return os.getenv(key, default)

def get_env_array(key: str, delimiter=",") -> List[str]:
    value = os.getenv(key)
    return value.split(delimiter) if value else []


# -------------------------------------------------
# Config (Base64 PEM keys)
# -------------------------------------------------

config = {
    "rsaPublicKeyBase64": get_env("RSA_PUBLIC_KEY_BASE64"),
    "rsaPrivateKeyBase64": get_env("RSA_PRIVATE_KEY_BASE64"),
}


# -------------------------------------------------
# Key loading helpers
# -------------------------------------------------

def load_public_key(public_key_base64: str):
    pem = base64.b64decode(public_key_base64)
    return serialization.load_pem_public_key(
        pem,
        backend=default_backend()
    )


def load_private_key(private_key_base64: str):
    pem = base64.b64decode(private_key_base64)
    return serialization.load_pem_private_key(
        pem,
        password=None,
        backend=default_backend()
    )


# -------------------------------------------------
# RSA encrypt / decrypt (Node.js compatible)
# crypto.publicEncrypt / privateDecrypt
# OAEP + SHA-256
# -------------------------------------------------

def rsa_encrypt(plaintext: str, public_key_base64: str) -> str:
    public_key = load_public_key(public_key_base64)

    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(ciphertext).decode()


def rsa_decrypt(ciphertext_base64: str, private_key_base64: str) -> str:
    private_key = load_private_key(private_key_base64)

    plaintext = private_key.decrypt(
        base64.b64decode(ciphertext_base64),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return plaintext.decode()


# -------------------------------------------------
# RSA key generation (utility)
# -------------------------------------------------

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return (
        base64.b64encode(public_pem).decode(),
        base64.b64encode(private_pem).decode(),
    )


# -------------------------------------------------
# Unit tests (pytest)
# -------------------------------------------------

def test_rsa_encrypt_decrypt_roundtrip():
    public_key_b64, private_key_b64 = generate_rsa_keypair()

    message = "hello rsa"
    encrypted = rsa_encrypt(message, public_key_b64)
    decrypted = rsa_decrypt(encrypted, private_key_b64)

    assert decrypted == message


# -------------------------------------------------
# Manual run
# -------------------------------------------------

if __name__ == "__main__":
    pub, priv = generate_rsa_keypair()

    print("Public Key (Base64 PEM):", pub[:60] + "...")
    print("Private Key (Base64 PEM):", priv[:60] + "...")

    encrypted = rsa_encrypt("secret message", pub)
    decrypted = rsa_decrypt(encrypted, priv)

    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)

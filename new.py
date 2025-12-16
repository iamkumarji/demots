import os
import base64
from typing import List
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
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
# Config (TS equivalent)
# -------------------------------------------------

config = {
    "securityIgnoreProperties": get_env_array("SECURITY_IGNORE_PROPERTIES") or [],
    "aesKeyBase64": get_env("AES256_KEY_BASE64"),
    "aesIVBase64": get_env("AES256_IV_BASE64"),
}


# -------------------------------------------------
# AES algorithm selector
# -------------------------------------------------

def get_algorithm_aes256cbc(key_base64: str) -> str:
    key = base64.b64decode(key_base64)

    if len(key) == 16:
        return "aes-128-cbc"
    elif len(key) == 32:
        return "aes-256-cbc"
    else:
        raise ValueError("Invalid AES key length")


# -------------------------------------------------
# AES encrypt / decrypt (Node.js compatible)
# -------------------------------------------------

def aes_encrypt(plaintext: str, key_base64: str, iv_base64: str) -> str:
    key = base64.b64decode(key_base64)
    iv = base64.b64decode(iv_base64)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(ciphertext).decode()


def aes_decrypt(ciphertext_base64: str, key_base64: str, iv_base64: str) -> str:
    key = base64.b64decode(key_base64)
    iv = base64.b64decode(iv_base64)

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(
        base64.b64decode(ciphertext_base64)
    ) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()


# -------------------------------------------------
# Unit tests (pytest)
# -------------------------------------------------

def test_should_return_aes_128_cbc():
    key = base64.b64encode(b"1234567890123456").decode()
    assert get_algorithm_aes256cbc(key) == "aes-128-cbc"


def test_should_return_aes_256_cbc():
    key = base64.b64encode(b"12345678901234567890123456789012").decode()
    assert get_algorithm_aes256cbc(key) == "aes-256-cbc"


def test_encrypt_decrypt_roundtrip():
    key = base64.b64encode(b"12345678901234567890123456789012").decode()
    iv = base64.b64encode(b"1234567890123456").decode()
    message = "hello world"

    encrypted = aes_encrypt(message, key, iv)
    decrypted = aes_decrypt(encrypted, key, iv)

    assert decrypted == message


# -------------------------------------------------
# Manual run
# -------------------------------------------------

if __name__ == "__main__":
    key = base64.b64encode(b"12345678901234567890123456789012").decode()
    iv = base64.b64encode(b"1234567890123456").decode()

    encrypted = aes_encrypt("secret message", key, iv)
    decrypted = aes_decrypt(encrypted, key, iv)

    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)

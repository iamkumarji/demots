# helpers.py
import os
import base64

# -------------------------
# Environment helpers
# -------------------------

def get_env(key: str, default=None):
    return os.getenv(key, default)

def get_env_array(key: str, delimiter=","):
    value = os.getenv(key)
    return value.split(delimiter) if value else []


# -------------------------
# Config (equivalent to TS)
# -------------------------

config = {
    "securityIgnoreProperties": get_env_array("SECURITY_IGNORE_PROPERTIES") or [],
    "aesKeyBase64": get_env("AES256_KEY_BASE64"),
    "aesIVBase64": get_env("AES256_IV_BASE64"),
}


# -------------------------
# AES algorithm selector
# -------------------------

def get_algorithm_aes256cbc(key_base64: str) -> str:
    key = base64.b64decode(key_base64)

    if len(key) == 16:
        return "aes-128-cbc"
    elif len(key) == 32:
        return "aes-256-cbc"
    else:
        raise ValueError("Invalid AES key length")


# -------------------------
# Unit tests (pytest style)
# -------------------------

def test_should_return_aes_128_cbc():
    key = base64.b64encode(b"1234567890123456").decode()
    assert get_algorithm_aes256cbc(key) == "aes-128-cbc"


def test_should_return_aes_256_cbc():
    key = base64.b64encode(b"12345678901234567890123456789012").decode()
    assert get_algorithm_aes256cbc(key) == "aes-256-cbc"


# -------------------------
# Optional manual run
# -------------------------

if __name__ == "__main__":
    print("Config:", config)
    print("AES-128:", get_algorithm_aes256cbc(
        base64.b64encode(b"1234567890123456").decode()
    ))
    print("AES-256:", get_algorithm_aes256cbc(
        base64.b64encode(b"12345678901234567890123456789012").decode()
    ))

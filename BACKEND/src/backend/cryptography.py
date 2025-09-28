import base64
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pydantic import SecretStr

from backend.config import settings

KDF_ITERATIONS = 200_000
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12

# 🔐 Keys generated with: secrets.token_hex(32)
MASTER_KEY = settings.master_key_bytes
HMAC_KEY = settings.hmac_key_bytes


def derive_key(user_id: str, salt: bytes | None = None) -> bytes:
    if salt is None:
        salt = user_id.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA3_512(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(MASTER_KEY)


def encrypt_secret(secret: SecretStr, user_id: str) -> str:
    key = derive_key(user_id)
    nonce = secrets.token_bytes(AES_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(
        nonce,
        secret.get_secret_value().encode("utf-8"),
        None,
    )

    # Combine nonce + ciphertext for storage
    encrypted = base64.urlsafe_b64encode(nonce + ciphertext)
    return encrypted.decode("utf-8")


def decrypt_secret(encrypted_secret: str, user_id: str) -> SecretStr:
    key = derive_key(user_id)
    encrypted_data = base64.urlsafe_b64decode(encrypted_secret)

    nonce = encrypted_data[:AES_NONCE_SIZE]
    ciphertext = encrypted_data[AES_NONCE_SIZE:]

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return SecretStr(plaintext.decode("utf-8"))


def computer_hash(value: SecretStr | str | bytes) -> str:
    if isinstance(value, SecretStr):
        value = value.get_secret_value()

    if isinstance(value, str):
        value = value.encode("utf-8")

    h = hmac.HMAC(HMAC_KEY, hashes.SHA3_512(), backend=default_backend())
    h.update(value)

    digest = h.finalize()

    return base64.urlsafe_b64encode(digest).decode("utf-8")

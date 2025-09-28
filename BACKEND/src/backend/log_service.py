import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
from pathlib import Path

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from backend.utils import get_utc_now

import backend.utils
from backend.config import settings

LOG_CHAIN_FILE = "log_chain.json"
AES_KEY_FILE = "aes_key.bin"

logger = logging.getLogger(__name__)
LOG_SERVER_AVAILABLE = True


async def check_log_server_health() -> None:
    global LOG_SERVER_AVAILABLE

    while True:
        try:
            # Uniquement vérifier si on est en mode maintenance
            if not LOG_SERVER_AVAILABLE:
                response = requests.get(
                    "https://localhost:8001/health",
                    timeout=5,
                )

                if response.status_code == 200:  # noqa: PLR2004
                    LOG_SERVER_AVAILABLE = True
                    logger.info(
                        "Serveur de logs à nouveau disponible,"
                        " mode normal activé",
                    )

                    # Log de reprise de service
                    try:
                        with Path("log_server_recovery.txt").open("a") as f:
                            f.write(
                                f"{get_utc_now().isoformat()} - Le serveur"
                                f" de logs est à nouveau disponible\n",
                            )
                    except Exception:
                        pass
        except Exception:
            pass

        # Vérifier toutes les 10 secondes
        await asyncio.sleep(10)


def get_last_hash() -> str | None:
    if not Path(LOG_CHAIN_FILE).exists():
        return None
    with Path(LOG_CHAIN_FILE).open("rb") as f:
        try:
            hash_info = json.loads(f.read())
            return hash_info.get("current_hash")
        except json.JSONDecodeError:
            return None


def update_last_hash(current_hash: str) -> None:
    with Path(LOG_CHAIN_FILE).open("w") as f:
        json.dump({"current_hash": current_hash}, f)


def compute_hash(log: dict) -> str:
    return hashlib.sha3_512(
        json.dumps(log, sort_keys=True).encode(),
    ).hexdigest()


def encrypt_log(log_dict: dict) -> dict:
    """Encrypts a given log dictionary using AES-256 encryption in GCM mode and encrypts the AES key using
    an RSA public key. The function ensures secure transmission of the logs by employing
    symmetric encryption for the data and asymmetric encryption for the key.

    This implementation works by:
    1. Generating a cryptographically secure AES-256 encryption key and nonce for the log data.
    2. Encrypting the log dictionary using AES encryption in GCM mode.
    3. Encrypting the AES key using the server's RSA public key.
    4. Returning the encrypted AES key, nonce, ciphertext and authentication tag in Base64 encoding.

    :param log_dict: Dictionary containing log data to be encrypted.
    :type log_dict: dict
    :return: A dictionary containing Base64-encoded encrypted key, nonce, ciphertext and tag.
    :rtype: dict
    """
    with Path(settings.public_key_path).open("rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # Sérialiser les données
    data = json.dumps(log_dict).encode()

    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    # Chiffrer les données avec AES GCM
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag

    # Chiffrer la clé AES avec la clé publique RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "encrypted_data": base64.b64encode(encrypted_data).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def secure_log(message: str, level: str = "INFO", **extra_data) -> bool:
    global LOG_SERVER_AVAILABLE

    try:
        timestamp_iso = backend.utils.get_utc_now().isoformat()
        log_entry = {
            "message": message,
            "level": level,
            "previous_hash": get_last_hash(),
            "created_at": timestamp_iso,
        }

        # Ajouter les données supplémentaires
        if extra_data:
            log_entry.update(extra_data)

        log_entry["current_hash"] = compute_hash(log_entry)

        log_to_sign = dict(log_entry)
        signature = sign_log(log_to_sign)
        log_entry["backend_signature"] = signature

        encrypted = encrypt_log(log_entry)

        log_data = {
            "encrypted_key": encrypted["encrypted_key"],
            "nonce": encrypted["nonce"],  # Changé de "iv" à "nonce"
            "encrypted_data": encrypted["encrypted_data"],
            "tag": encrypted["tag"],  # Nouveau champ
            "signature": log_entry["backend_signature"],
            "created_at": log_entry["created_at"],
        }

        try:
            response = requests.post(
                "https://localhost:8001/logs",
                json=log_data,
                timeout=5,
                verify=False,
            )
            response.raise_for_status()

            # Serveur de logs est disponible, mettre à jour le statut si nécessaire
            if not LOG_SERVER_AVAILABLE:
                LOG_SERVER_AVAILABLE = True
                logger.info(
                    "Serveur de logs à nouveau disponible, mode normal activé",
                )

            # Sauvegarder le hash pour maintenir la chaîne
            update_last_hash(log_entry["current_hash"])
            return True

        except requests.exceptions.RequestException as e:
            # Journaliser l'erreur critique
            error_msg = (
                f"ALERTE CRITIQUE: Le serveur de logs ne répond pas: {e!s}"
            )
            logger.critical(error_msg)

            # Enregistrer localement l'incident
            try:
                with Path("log_server_failure.txt").open("a") as f:
                    f.write(
                        f"{backend.utils.get_utc_now().isoformat()} "
                        f"- {error_msg}\n",
                    )
                    f.flush()
                    os.fsync(f.fileno())
            except Exception as write_error:
                msg = (
                    f"Impossible d'écrire dans le "
                    f"fichier de log: {write_error}"
                )
                logger.exception(msg)

            # Activer le mode maintenance
            LOG_SERVER_AVAILABLE = False
            logger.critical(
                "MODE MAINTENANCE ACTIVÉ: Le serveur de logs est inaccessible",
            )

            return False

    except Exception as e:
        msg = f"Erreur lors de la sécurisation du log: {e!s}"
        logger.exception(msg)
        raise


def sign_log(log_dict: dict) -> str:
    with Path(settings.private_key_path).open("rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    log_dict_copy = dict(log_dict)
    log_bytes = json.dumps(log_dict_copy, sort_keys=True).encode()

    signature = private_key.sign(
        log_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA3_512()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA3_512(),
    )

    return base64.b64encode(signature).decode()

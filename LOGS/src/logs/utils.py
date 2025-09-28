import base64
import hashlib
import json
import logging
import traceback
from datetime import datetime, timezone
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from logs.constant import IPV4_PATTERN, IPV6_PATTERN, ALLOWED_CHARS

logger = logging.getLogger(__name__)

# [Fonctions existantes inchangées]


def get_utc_now() -> datetime:
    """Get the current UTC time.

    :return: The current UTC time.
    """
    return datetime.now(timezone.utc)


def get_utc_now_milliseconds() -> int:
    """Get the current UTC time in milliseconds.

    :return: The current UTC time in milliseconds.
    """
    return int(get_utc_now().timestamp() * 1000)


def milliseconds_to_datetime_UTC(milliseconds: int) -> datetime:  # noqa: N802
    """Convert milliseconds since epoch to UTC datetime.

    :param milliseconds: Milliseconds since epoch.
    :return: UTC datetime.
    """
    return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)


def decrypt_log(
    encrypted_key_b64: str,
    nonce_b64: str,
    encrypted_data_b64: str,
    tag_b64: str,
) -> dict:
    with Path("private_key_log.key").open("rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    encrypted_key = base64.b64decode(encrypted_key_b64)
    nonce = base64.b64decode(nonce_b64)
    encrypted_data = base64.b64decode(encrypted_data_b64)
    tag = base64.b64decode(tag_b64)

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    # Utiliser GCM au lieu de CBC
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce, tag),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

    return json.loads(plaintext.decode())


def verify_signature(log_dict: dict, signature_b64: str) -> None:
    with Path("backend_public_key.pem").open("rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    signature = base64.b64decode(signature_b64)

    log_dict_copy = dict(log_dict)
    log_dict_copy.pop("backend_signature", None)
    log_bytes = json.dumps(log_dict_copy, sort_keys=True).encode()


    try:
        # Utiliser PSS au lieu de PKCS1v15
        public_key.verify(
            signature,
            log_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA3_512()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA3_512(),
        )
        print("[INFO] Signature verification successful")
    except Exception as e:
        print(InvalidSignature)
        print("[ERROR] Signature verification failed:")
        print("[DEBUG] log_bytes to verify:", log_bytes.decode())
        print("[DEBUG] signature (base64):", signature_b64)
        print("[DEBUG] signature (raw bytes):", signature.hex())
        print(f"[ERROR] Exception: {e!s}")
        traceback.print_exc()
        raise


def compute_etag(log_dict: dict) -> str:
    return hashlib.sha3_512(
        json.dumps(log_dict, sort_keys=True).encode(),
    ).hexdigest()


def sign_log(log_dict: dict) -> str:
    with Path("private_key_log.key").open("rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    log_bytes = json.dumps(log_dict, sort_keys=True).encode()

    signature = private_key.sign(
        log_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA3_512()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA3_512(),
    )

    return base64.b64encode(signature).decode()


# [Nouvelles fonctions de sécurité]


def sanitize_query_params(params: dict) -> dict:
    """Sanitise les paramètres de requête pour MongoDB

    :param params: Dictionnaire de paramètres
    :return: Dictionnaire sanitisé
    """
    # Liste des opérateurs MongoDB autorisés
    ALLOWED_MONGO_OPERATORS = {"$gte", "$lte", "$eq", "$in", "$gt", "$lt"}

    sanitized = {}

    for key, value in params.items():
        # Vérification des types
        if isinstance(value, str):
            # Sanitiser les chaînes
            sanitized[key] = value
        elif isinstance(value, (int, float, bool)):
            # Les types primitifs sont sûrs
            sanitized[key] = value
        elif isinstance(value, dict):
            # Pour les opérateurs MongoDB comme $gte, $lte
            safe_dict = {}
            for op_key, op_value in value.items():
                if (
                    op_key.startswith("$")
                    and op_key in ALLOWED_MONGO_OPERATORS
                ):
                    if isinstance(op_value, (str, int, float, bool)):
                        safe_dict[op_key] = op_value
                # Clé non-opérateur - traiter comme une sous-structure
                elif isinstance(op_value, (str, int, float, bool)):
                    safe_dict[op_key] = op_value

            if (
                safe_dict
            ):  # Seulement si le dictionnaire sanitisé n'est pas vide
                sanitized[key] = safe_dict
        else:
            # Ignorer les types non sûrs
            logger.warning(
                f"Type non sécurisé ignoré pour {key}: {type(value)}",
            )

    return sanitized


def validate_ip_address(ip: str) -> bool:
    """Valide le format d'une adresse IP (IPv4 ou IPv6)"""
    if not isinstance(ip, str):
        return False

    return bool(IPV4_PATTERN.match(ip) or IPV6_PATTERN.match(ip))


def validate_route(route: str) -> bool:
    """Valide le format d'une route d'API"""
    if not isinstance(route, str):
        return False

    # Doit commencer par /
    if not route.startswith("/"):
        return False

    # Vérifier caractères autorisés
    return bool(ALLOWED_CHARS.match(route))


async def safe_mongo_find(collection, query, **kwargs):
    """Wrapper sécurisé pour les requêtes MongoDB find

    :param collection: Collection MongoDB
    :param query: Requête à exécuter
    :param kwargs: Arguments supplémentaires pour find
    :return: Résultat de la requête
    """
    # Sanitiser la requête
    safe_query = sanitize_query_params(query)

    # Vérifier si la requête est vide après sanitisation
    if not safe_query and query:
        logger.warning(f"La requête a été vidée après sanitisation: {query}")
        raise ValueError("Requête non sécurisée")

    # Exécuter la requête sanitisée
    return await collection.find(safe_query, **kwargs)


async def safe_mongo_count(collection, query):
    """Wrapper sécurisé pour les requêtes MongoDB count_documents

    :param collection: Collection MongoDB
    :param query: Requête à exécuter
    :return: Nombre de documents
    """
    # Sanitiser la requête
    safe_query = sanitize_query_params(query)

    # Vérifier si la requête est vide après sanitisation
    if not safe_query and query:
        logger.warning(f"La requête a été vidée après sanitisation: {query}")
        raise ValueError("Requête non sécurisée")

    # Exécuter la requête sanitisée
    return await collection.count_documents(safe_query)


async def safe_mongo_find_one(collection, query, **kwargs):
    """Wrapper sécurisé pour les requêtes MongoDB find_one

    :param collection: Collection MongoDB
    :param query: Requête à exécuter
    :param kwargs: Arguments supplémentaires pour find_one
    :return: Document trouvé ou None
    """
    # Si la requête est vide, la laisser telle quelle (cas légitime pour find_one)
    if not query:
        return await collection.find_one(query, **kwargs)

    # Sanitiser la requête
    safe_query = sanitize_query_params(query)

    # Vérifier si la requête est vide après sanitisation
    if not safe_query and query:
        logger.warning(f"La requête a été vidée après sanitisation: {query}")
        raise ValueError("Requête non sécurisée")

    # Exécuter la requête sanitisée
    return await collection.find_one(safe_query, **kwargs)

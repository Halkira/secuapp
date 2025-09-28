import json
import logging
import uuid
from collections.abc import Generator

from fastapi.exceptions import HTTPException
from pydantic import EmailStr
from redis.asyncio import Redis
from sqlmodel import Session
from starlette import status

from backend import models, utils
from backend.config import settings
from backend.constants import REDIS_TEMP_KEY_TTL_SECONDS
from backend.database import User

logger = logging.getLogger(__name__)

redis_client: Redis = Redis.from_url(settings.redis_url, decode_responses=True)


async def init_redis() -> None:
    """Initialize the Redis connection."""
    await redis_client.ping()


def get_redis() -> Generator[Redis]:
    yield redis_client


def get_redis_client() -> Redis:
    return redis_client


async def close_redis() -> None:
    """Close the Redis connection."""
    await redis_client.close()
    await redis_client.connection_pool.disconnect()


async def add_email_token(
    redis: Redis,
    user_id: uuid.UUID,
    token_hash: str,
) -> None:
    await redis.set(
        f"email_token:{token_hash}",
        str(user_id),
        ex=settings.session_ttl,
    )


async def get_user_id_by_email_token(
    redis: Redis,
    token_hash: str,
) -> uuid.UUID | None:
    user_id = await redis.get(f"email_token:{token_hash}")

    if user_id is None:
        return None

    return uuid.UUID(user_id)


async def handle_add_device_request(
    email: EmailStr,
    new_device_pk: str,
    db: Session,
    device_id: models.Base64Encoded,
    redis: Redis = None,
) -> dict:
    """Gère la requête d'ajout d'un nouvel appareil depuis le frontend.
    Stocke la clé publique du nouvel appareil dans Redis avec une expiration.

    Args:
        email (str): L'ID de l'utilisateur qui tente de se connecter.
        new_device_pk (str): La clé publique (PK_device_B) du nouvel appareil, encodée (ex: JWK).
        device_id (str, optional): Un ID temporaire unique généré par l'Appareil B.
        redis (Redis, optional): Instance de Redis. Si None, utilise la connexion par défaut.
        db (None, optional): Instance de la base de données. Si None, aucune opération DB n'est effectuée.

    Returns:
        dict: Un dictionnaire contenant l'ID temporaire utilisé pour la clé Redis,
              et le statut de l'opération.

    """  # noqa: E501
    if not email or not new_device_pk:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="user_id et new_device_pk sont requis.",
        )

    user_id = User.get_user_id_by_email(email, db=db)
    user_id = str(user_id)  # Ensure user_id is a string for Redis key

    redis_key = f"device_approval:{user_id}:{device_id}"

    data_to_store = {
        "user_id": user_id,
        "device_id": device_id,
        "pubkey_device": new_device_pk,
        "request_timestamp": utils.get_utc_now().isoformat(),
        "status": "pending",
    }

    json_data_string = json.dumps(data_to_store)

    try:
        await redis.setex(
            redis_key,
            REDIS_TEMP_KEY_TTL_SECONDS,
            json_data_string,
        )
    except Exception as e:
        log_msg = f"Erreur lors du stockage dans Redis : {e}"
        logger.exception(log_msg)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur interne lors de l'enregistrement de la demande.",
        ) from e

    log_msg = (
        f"Demande d'ajout d'appareil stockée dans Redis : '{redis_key}'",
        f"Expiration dans {REDIS_TEMP_KEY_TTL_SECONDS} secondes.",
    )

    logger.info(log_msg)

    return {
        "status": "success",
        "message": "Demande d'ajout d'appareil enregistrée. En attente d'approbation.",  # noqa: E501
        "device_id": device_id,
        "redis_key_used": redis_key,
    }


async def get_device_requests(user_id: uuid.UUID, redis: Redis) -> list:
    """Récupère les demandes d'ajout d'appareil en attente pour un utilisateur donné.

    Args:
        user_id (str): L'ID de l'utilisateur.
        redis (Redis): Instance de Redis.

    Returns:
        list: Une liste de dictionnaires contenant les détails des demandes d'ajout d'appareil.

    """  # noqa: E501
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="user_id est requis.",
        )
    user_id = str(user_id)
    keys = await redis.keys(f"device_approval:{user_id}:*")
    requests = []

    for key in keys:
        data = await redis.get(key)
        if data:
            obj = json.loads(data)
            if obj.get("status") == "pending":
                requests.append(json.loads(data))

    return requests


async def delete_device_request(
    redis: Redis,
    user_id: uuid.UUID,
    device_id: models.Base64Encoded,
) -> None:
    """Supprime une demande d'ajout d'appareil de Redis.

    Args:
        redis (Redis): Instance de Redis.
        user_id (str): L'ID de l'utilisateur.
        device_id (str): L'ID temporaire de la demande à supprimer.

    """
    if not user_id or not device_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="user_id et new_device_temp_id sont requis.",
        )
    user_id = str(user_id)  # Ensure user_id is a string for Redis key
    keys = await redis.keys(f"device_approval:{user_id}:{device_id}")
    for key in keys:
        await redis.delete(key)


async def delete_email_token(
    redis: Redis,
    token_hash: str,
) -> None:
    await redis.delete(f"email_token:{token_hash}")


async def check_device_approval(
    user_id: uuid.UUID,
    device_id: models.Base64Encoded,
    redis: Redis,
) -> bool:
    """Vérifie si une demande d'ajout d'appareil est approuvée.

    Args:
        user_id (str): L'ID de l'utilisateur.
        device_id (str): L'ID temporaire de la demande à vérifier.
        redis (Redis): Instance de Redis.

    Returns:
        bool: True si la demande est approuvée, False sinon.

    """
    if not user_id or not device_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="user_id et new_device_temp_id sont requis.",
        )

    user_id = str(user_id)  # Ensure user_id is a string for Redis key
    redis_key = f"device_approval:{user_id}:{device_id}"

    data = await redis.get(redis_key)

    if data:
        request_data = json.loads(data)
        return request_data.get("status") == "approved"

    return False


async def approve_device_request(
    user_id: uuid.UUID,
    device_id: models.Base64Encoded,
    redis: Redis,
) -> None:
    """Approuve une demande d'ajout d'appareil en mettant à jour son statut dans Redis.

    Args:
        user_id (str): L'ID de l'utilisateur.
        device_id (str): L'ID temporaire de la demande à approuver.
        redis (Redis): Instance de Redis.

    """  # noqa: E501
    if not user_id or not device_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="user_id et new_device_temp_id sont requis.",
        )

    user_id = str(user_id)  # Ensure user_id is a string for Redis key
    redis_key = f"device_approval:{user_id}:{device_id}"

    data = await redis.get(redis_key)

    if data:
        request_data = json.loads(data)
        request_data["status"] = "approved"
        await redis.set(redis_key, json.dumps(request_data))
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Demande non trouvée.",
        )

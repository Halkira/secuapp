import json
import logging
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from backend import log_service
from fastapi import HTTPException, status, Request

from backend import database, models, utils
from backend.database import Session as DBSession
from backend.database import StreamKey, Video
from backend.helper.common import VIDEOS_DIR, video_buffer

FILE_PATTERN = pattern = re.compile(r"^\d{8}_\d{6}\.json$")

logger = logging.getLogger(__name__)


async def save_last_moment(connection_id, user_id, session) -> None:  # noqa: ANN001
    """Sauvegarde les dernières images en fichier JSON."""
    if not video_buffer[connection_id]:
        logger.info("Buffer vide, aucune vidéo à sauvegarder")
        return

    stream_dir: Path = VIDEOS_DIR / connection_id
    stream_dir.mkdir(parents=True, exist_ok=True)

    timestamp = utils.get_utc_now().strftime("%Y%m%d_%H%M%S")
    json_filename: Path = stream_dir / f"{timestamp}.json"

    with json_filename.open("w") as f:
        json.dump(video_buffer[connection_id], f)

    size = json_filename.stat().st_size  # taille en octets

    video = Video(
        id=connection_id,
        owner_id=user_id,
        size=size,
        timestamp=utils.get_utc_now(),
    )
    Video.add_video(
        db=session,
        video=video,
    )

    log_msg = f"Données chiffrées sauvegardées en JSON: {json_filename}"
    logger.info(log_msg)


def list_videos_data(user_id: uuid.UUID | str, db: DBSession) -> dict:
    """Prépare les données des vidéos enregistrées avec leur taille et date de création."""  # noqa: E501
    if not VIDEOS_DIR.exists():
        return {"streams": {}}

    db_videos_id = [
        video.id
        for video in database.Video.get_videos_by_user_id(
            user_id=user_id,
            db=db,
        )
    ]

    streams = {}

    for stream_path in VIDEOS_DIR.iterdir():
        stream_id = stream_path.name

        if uuid.UUID(stream_id) not in db_videos_id:
            log_msg = f"Le flux {stream_id} n'est pas associé à l'utilisateur {user_id}"  # noqa: E501
            logger.warning(log_msg)
            continue

        if stream_path.is_dir():
            videos = []

            for file in stream_path.iterdir():
                # Obtenir la taille du fichier en octets
                file_size = file.stat().st_size

                # Obtenir la date de création/modification
                creation_timestamp = file.stat().st_ctime
                creation_date = datetime.fromtimestamp(
                    timestamp=creation_timestamp,
                    tz=timezone.utc,
                ).strftime("%Y-%m-%d %H:%M:%S")

                # Ajouter les informations du fichier
                videos.append(
                    {
                        "filename": file.name,
                        "size_bytes": file_size,
                        "size_human": format_size(file_size),
                        "creation_date": creation_date,
                    },
                )

            streams[stream_id] = videos

    return {"streams": streams}


def format_size(size_bytes: int) -> str:
    """Convertit une taille en octets en format lisible."""
    if size_bytes < 1024:  # noqa: PLR2004
        return f"{size_bytes} octets"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} Ko"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} Mo"
    return f"{size_bytes / (1024 * 1024 * 1024):.2f} Go"


def get_video_file(
    user_id: uuid.UUID,
    user_role: models.UserRole,
    video_id: uuid.UUID,
    db: DBSession,
    request: Request,
) -> Path:
    """Récupère un fichier JSON spécifique."""
    stream_path = VIDEOS_DIR / str(video_id)

    if not stream_path.exists() or not stream_path.is_dir():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Le flux vidéo n'existe pas",
        )

    own_video: bool = False

    match user_role:
        case models.UserRole.REGULAR:
            own_video = (
                database.Video.get_video_by_id_and_user_id(
                    user_id=user_id,
                    video_id=video_id,
                    db=db,
                )
                is not None
            )
        case models.UserRole.TRUSTED:
            own_video = any(
                shared_video.video_id == video_id
                for shared_video in database.SharedVideo.get_shared_videos_for_recipient(  # noqa: E501
                    db=db,
                    user_id=user_id,
                )
            )

    if not own_video:
        log_service.secure_log(
            message=f"Échec d'accès à la vidéo {video_id}",
            level="WARNING",
            user_id=user_id,
            action="get_video",
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent", "inconnu"),
            method=request.method,
            route=request.url.path,
            data={
                "video_id": video_id,
                "status": status_code,
                "error": str(e),
                "access_time": datetime.now(timezone.utc).isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vous n'êtes pas autorisé à accéder à cette vidéo",
        )

    video_file: Path | None = next(
        (
            f
            for f in stream_path.iterdir()
            if f.is_file() and pattern.match(f.name)
        ),
        None,
    )

    if video_file is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Aucun fichier vidéo trouvé pour ce flux",
        )

    return video_file


def delete_video_file(video_id, user_id, db) -> dict | None:  # noqa: ANN001, C901
    """Supprime un fichier ou répertoire vidéo, sa clé de stream et son entrée dans la table Video."""  # noqa: E501
    db_operation_success = False

    try:
        video = db.get(Video, video_id)
        if video and video.owner_id != user_id:
            raise HTTPException(  # noqa: TRY301
                status_code=403,
                detail="Vous n'êtes pas autorisé à supprimer cette vidéo",
            )

        if video:
            db.delete(video)

        stream_key = StreamKey.get_stream_key(db, stream_id=video_id)
        if stream_key and stream_key.owner_id != user_id:
            raise HTTPException(  # noqa: TRY301
                status_code=403,
                detail="Vous n'êtes pas autorisé à supprimer ce contenu",
            )

        if stream_key:
            db.delete(stream_key)

        # Commit une seule fois pour les deux suppressions
        db.commit()
        db_operation_success = True

    except Exception as e:
        # Rollback pour annuler toutes les opérations en cas d'erreur
        db.rollback()
        log_service.secure_log(
            message=f"Échec de suppression de la vidéo {video_id}",
            level="ERROR",
            user_id=user_id,
            action="delete_video",
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent", "inconnu"),
            method=request.method,
            route=request.url.path,
            data={
                "video_id": video_id,
                "status": "500 Internal Server Error"
                if "not found" not in str(e).lower()
                else "404 Not Found",
                "error": str(e),
                "deletion_time": datetime.now(timezone.utc).isoformat(),
            },
        )

        raise HTTPException(
            status_code=500,
            detail=f"Erreur lors de la suppression en base de données: {e!s}",
        ) from e

    if not db_operation_success:
        return None

    stream_path = f"{VIDEOS_DIR}/{video_id}"

    if os.path.isdir(stream_path):  # noqa: PTH112
        try:
            shutil.rmtree(stream_path)
            return {  # noqa: TRY300
                "status": "success",
                "message": f"Stream {video_id} et sa clé supprimés avec succès",  # noqa: E501
            }
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de la suppression du répertoire: {e!s}",
            ) from e

    elif os.path.isfile(stream_path) and stream_path.endswith(".json"):  # noqa: PTH113
        try:
            os.remove(stream_path)  # noqa: PTH107
            return {  # noqa: TRY300
                "status": "success",
                "message": f"Fichier {video_id} supprimé avec succès",
            }
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de la suppression du fichier: {e!s}",
            ) from e

    raise HTTPException(
        status_code=404,
        detail="Fichier ou répertoire non trouvé",
    )

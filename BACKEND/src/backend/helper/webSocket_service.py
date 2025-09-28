import json  # noqa: N999
import logging
import uuid

from fastapi import WebSocket, WebSocketDisconnect
from sqlmodel import Session as DBSession

from backend import utils
from backend.database import Stream
from backend.helper.common import (
    BUFFER_FRAMES,
    active_connections,
    stream_observers,
    video_buffer,
)
from backend.helper.video_service import save_last_moment

logger = logging.getLogger(__name__)


async def handle_stream_connection(  # noqa: C901, PLR0912, PLR0915
    websocket: WebSocket,
    user_id: uuid.uuid4,
    session: DBSession,
) -> None:
    """Gère une nouvelle connexion de stream WebSocket."""
    await websocket.accept()

    log_msg = f"Nouvelle connexion de stream pour l'utilisateur {user_id}"
    logger.info(log_msg)

    connection_id: str = str(uuid.uuid4())
    active_connections[connection_id] = websocket
    video_buffer[connection_id] = []

    # Envoyer l'ID de connexion au client
    await websocket.send_text(json.dumps({"connection_id": connection_id}))

    new_stream: Stream = Stream(
        id=connection_id,
        owner_id=user_id,
        created_at=utils.get_utc_now(),
    )
    Stream.add_stream(db=session, stream=new_stream)

    log_msg = f"Nouvelle connexion établie: {connection_id}"
    logger.info(log_msg)

    try:
        while True:
            # Recevoir les frames du client
            data = await websocket.receive_text()

            # Ajouter la frame au buffer avec un timestamp
            frame_data = {
                "timestamp": utils.get_utc_now_milliseconds(),
                "data": data,
            }

            # Ajouter au buffer et limiter sa taille
            video_buffer[connection_id].append(frame_data)
            if len(video_buffer[connection_id]) > BUFFER_FRAMES:
                video_buffer[connection_id] = video_buffer[connection_id][
                    -BUFFER_FRAMES:
                ]

            # Diffuser aux observateurs
            if stream_observers.get(connection_id):
                observers = stream_observers[connection_id].copy()
                disconnected_observers = []

                for observer in observers:
                    try:
                        await observer.send_text(data)
                    except Exception:  # noqa: BLE001
                        disconnected_observers.append(observer)

                # Nettoyer les observateurs déconnectés
                for observer in disconnected_observers:
                    if (
                        connection_id in stream_observers
                        and observer in stream_observers[connection_id]
                    ):
                        stream_observers[connection_id].remove(observer)

                # Si plus d'observateurs, nettoyer la liste
                if (
                    connection_id in stream_observers
                    and not stream_observers[connection_id]
                ):
                    del stream_observers[connection_id]

    except WebSocketDisconnect:
        log_msg = f"Client déconnecté: {connection_id}"
        logger.info(log_msg)

        if video_buffer.get(connection_id):
            await save_last_moment(connection_id, user_id, session)

    except Exception as e:
        log_msg = f"Erreur dans le stream {connection_id}: {e}"
        logger.exception(log_msg)

        if video_buffer.get(connection_id):
            await save_last_moment(connection_id, user_id, session)

    finally:
        # Nettoyer les ressources
        if connection_id in active_connections:
            del active_connections[connection_id]
        if connection_id in video_buffer:
            del video_buffer[connection_id]
        if connection_id in stream_observers:
            for observer in stream_observers[connection_id]:
                try:
                    await observer.send_text(
                        json.dumps({"error": "Le stream a été fermé"}),
                    )
                    await observer.close()
                except Exception as e:
                    log_msg = f"Erreur lors de la fermeture de l'observateur {observer}: {e}"  # noqa: E501
                    logger.exception(log_msg)
            del stream_observers[connection_id]


async def handle_watch_connection(
    websocket: WebSocket,
    connection_id: str,
) -> None:
    """Gère une connexion pour observer un stream."""
    await websocket.accept()

    # Vérifier si le stream demandé existe
    if connection_id not in active_connections:
        await websocket.send_text(
            json.dumps({"error": "Le stream demandé n'existe pas"}),
        )
        await websocket.close()
        return

    # Ajouter cet observateur
    if connection_id not in stream_observers:
        stream_observers[connection_id] = []
    stream_observers[connection_id].append(websocket)

    try:
        while True:
            await websocket.receive_text()
    except Exception as e:
        log_msg = (
            f"Erreur dans la connexion d'observation {connection_id}: {e}"
        )
        logger.exception(log_msg)
    finally:
        if (
            connection_id in stream_observers
            and websocket in stream_observers[connection_id]
        ):
            stream_observers[connection_id].remove(websocket)
            if not stream_observers[connection_id]:
                del stream_observers[connection_id]

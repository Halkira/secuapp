import uuid
from typing import Self
import logging
from aiortc import (
    MediaStreamTrack,
    RTCIceCandidate,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.contrib.media import MediaRelay
from backend import log_service
from backend.helper.common import (
    active_connections,
    webrtc_connections,
    webrtc_observers,
)

logger = logging.getLogger(__name__)

relay = MediaRelay()


class RelayTrack(MediaStreamTrack):
    """Un MediaStreamTrack qui relaie les frames d'une source à plusieurs observateurs."""  # noqa: E501

    def __init__(self, track) -> Self:  # noqa: ANN001
        super().__init__()
        self.track = track
        self.kind = track.kind

    async def recv(self):  # noqa: ANN201
        return await self.track.recv()


async def cleanup_connection(connection_id) -> None:  # noqa: ANN001
    """Nettoie une connexion WebRTC et ses observateurs."""
    if connection_id not in webrtc_connections:
        log_msg = f"Tentative de nettoyage d'une connexion inexistante: {connection_id}"  # noqa: E501
        logger.info(log_msg)
        return

    try:
        # Fermer la connexion principale
        pc = webrtc_connections[connection_id]["pc"]
        await pc.close()

        # Fermer les connexions des observateurs
        if connection_id in webrtc_observers:
            for observer in webrtc_observers[connection_id]:
                await observer["pc"].close()
            del webrtc_observers[connection_id]

        # Supprimer la connexion
        if connection_id in webrtc_connections:
            del webrtc_connections[connection_id]
            log_msg = f"Connexion WebRTC fermée: {connection_id}"
            logger.info(log_msg)
    except Exception as e:
        log_msg = (
            f"Erreur lors du nettoyage de la connexion {connection_id}: {e}"
        )
        logger.exception(log_msg)


async def cleanup_observer(connection_id, observer_id) -> None:  # noqa: ANN001
    """Nettoie une connexion d'observateur."""
    if connection_id not in webrtc_observers:
        return

    webrtc_observers[connection_id] = [
        obs
        for obs in webrtc_observers[connection_id]
        if obs["id"] != observer_id
    ]

    if not webrtc_observers[connection_id]:
        del webrtc_observers[connection_id]

    log_msg = f"Observateur WebRTC déconnecté: {observer_id} du stream {connection_id}"  # noqa: E501
    logger.info(log_msg)


async def process_webrtc_offer(
    offer_sdp,  # noqa: ANN001
    offer_type,  # noqa: ANN001
    connection_id,  # noqa: ANN001
) -> dict[str, str]:
    """Traite une offre WebRTC et retourne une réponse."""
    if not connection_id or connection_id not in active_connections:
        return {"error": "ID de connexion invalide ou non reconnu"}

    # Créer une connexion pour ce client
    pc = RTCPeerConnection()
    webrtc_connections[connection_id] = {"pc": pc, "tracks": []}

    @pc.on("track")
    def on_track(track) -> None:  # noqa: ANN001
        log_msg = f"Track reçu: {track.kind}"
        logger.info(log_msg)

        if track.kind == "video":
            # Créer un relai pour ce track
            relayed_track = relay.subscribe(track)
            webrtc_connections[connection_id]["tracks"].append(relayed_track)

    @pc.on("iceconnectionstatechange")
    async def on_iceconnectionstatechange() -> None:
        if pc.iceConnectionState in {"failed", "closed"}:
            await cleanup_connection(connection_id)

    @pc.on("connectionstatechange")
    async def on_connectionstatechange() -> None:
        if pc.connectionState in {"failed", "closed"}:
            await cleanup_connection(connection_id)

    offer = RTCSessionDescription(sdp=offer_sdp, type=offer_type)
    await pc.setRemoteDescription(offer)
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)

    return {
        "sdp": pc.localDescription.sdp,
        "type": pc.localDescription.type,
        "connection_id": connection_id,
    }


async def process_ice_candidate(
    connection_id,  # noqa: ANN001
    candidate_init,  # noqa: ANN001
) -> dict[str, str]:
    """Traite un candidat ICE."""
    if connection_id not in webrtc_connections:
        return {"error": "Connection non trouvée"}

    pc = webrtc_connections[connection_id]["pc"]
    candidate = RTCIceCandidate(
        component=candidate_init.get("component", 1),
        foundation=candidate_init.get("foundation", ""),
        ip=candidate_init.get("ip", ""),
        port=candidate_init.get("port", 0),
        priority=candidate_init.get("priority", 0),
        protocol=candidate_init.get("protocol", ""),
        type=candidate_init.get("type", ""),
        sdpMid=candidate_init.get("sdpMid"),
        sdpMLineIndex=candidate_init.get("sdpMLineIndex"),
    )

    await pc.addIceCandidate(candidate)
    return {"status": "success"}


async def create_watch_connection(
    connection_id,  # noqa: ANN001
    offer_sdp,  # noqa: ANN001
    offer_type,  # noqa: ANN001
) -> dict[str, str]:
    """Crée une connexion pour regarder un stream WebRTC."""
    if connection_id not in active_connections:
        return {"error": "Le stream demandé n'existe pas"}

    if connection_id not in webrtc_connections:
        return {"error": "Ce stream n'a pas de connexion WebRTC active"}

    pc = RTCPeerConnection()
    observer_id = str(uuid.uuid4())

    if connection_id not in webrtc_observers:
        webrtc_observers[connection_id] = []

    webrtc_observers[connection_id].append({"id": observer_id, "pc": pc})

    for track in webrtc_connections[connection_id]["tracks"]:
        cloned_track = RelayTrack(track)
        pc.addTrack(cloned_track)

    @pc.on("iceconnectionstatechange")
    async def on_iceconnectionstatechange() -> None:
        if pc.iceConnectionState in {"failed", "closed"}:
            await cleanup_observer(connection_id, observer_id)

    @pc.on("connectionstatechange")
    async def on_connectionstatechange() -> None:
        if pc.connectionState in {"failed", "closed"}:
            await cleanup_observer(connection_id, observer_id)

    offer = RTCSessionDescription(sdp=offer_sdp, type=offer_type)
    await pc.setRemoteDescription(offer)
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)

    return {
        "sdp": pc.localDescription.sdp,
        "type": pc.localDescription.type,
        "observer_id": observer_id,
    }


async def process_observer_ice_candidate(
    connection_id,  # noqa: ANN001
    observer_id,  # noqa: ANN001
    candidate_init,  # noqa: ANN001
) -> dict[str, str]:
    """Traite un candidat ICE d'un observateur."""
    if connection_id not in webrtc_observers:
        return {"error": "Stream non trouvé"}

    observer = next(
        (
            obs
            for obs in webrtc_observers[connection_id]
            if obs["id"] == observer_id
        ),
        None,
    )
    if not observer:
        return {"error": "Observateur non trouvé"}

    pc = observer["pc"]
    candidate = RTCIceCandidate(
        component=candidate_init.get("component", 1),
        foundation=candidate_init.get("foundation", ""),
        ip=candidate_init.get("ip", ""),
        port=candidate_init.get("port", 0),
        priority=candidate_init.get("priority", 0),
        protocol=candidate_init.get("protocol", ""),
        type=candidate_init.get("type", ""),
        sdpMid=candidate_init.get("sdpMid"),
        sdpMLineIndex=candidate_init.get("sdpMLineIndex"),
    )

    await pc.addIceCandidate(candidate)
    return {"status": "success"}


def check_webrtc_availability(connection_id) -> dict[str, str | bool]:  # noqa: ANN001
    """Vérifie si un stream a une connexion WebRTC active."""
    if connection_id not in active_connections:
        return {"error": "Le stream demandé n'existe pas", "has_webrtc": False}

    has_webrtc = connection_id in webrtc_connections
    return {"has_webrtc": has_webrtc}

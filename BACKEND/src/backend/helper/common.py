from pathlib import Path

from backend import utils

# Stockage pour les connexions actives
active_connections = {}
stream_observers = {}

# Stockage temporaire pour les frames vidéo
video_buffer = {}
BUFFER_SIZE = 15  # secondes
BUFFER_FRAMES = BUFFER_SIZE * 24  # 15 secondes à 24 fps

# Stockage pour les connexions WebRTC
webrtc_connections = {}
webrtc_observers = {}

# Dossier pour sauvegarder les vidéos
VIDEOS_DIR = Path("videos")
VIDEOS_DIR.mkdir(parents=True, exist_ok=True)


def list_active_streams_data() -> dict:
    """Prépare les données des streams actifs."""
    streams = []
    current_time = utils.get_utc_now().strftime("%Y-%m-%d %H:%M:%S")

    for stream_id in active_connections:
        observer_count = len(stream_observers.get(stream_id, []))
        has_webrtc = stream_id in webrtc_connections

        streams.append(
            {
                "id": stream_id,
                "observers": observer_count,
                "buffer_frames": len(video_buffer.get(stream_id, [])),
                "active_since": current_time,
                "has_webrtc": has_webrtc,
            },
        )

    return {"active_streams": streams}

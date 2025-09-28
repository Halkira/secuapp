import React, { useEffect, useState } from "react";
import { SharedVideo } from "../components/Video.tsx";
import Stream from "../components/Stream.tsx";
import sessionManager from "../../components/sessionManager.tsx";


interface SharedVideoData {
    id: string;
    shared_at: string;
    video_id: string;
    recipient_id: string;
    owner_id: string;
    shared_encryption_key: string;
}

// Même mise à jour pour SharedStreamData
interface SharedStreamData {
    id: string;
    shared_at: string;
    stream_id: string;
    recipient_id: string;
    owner_id: string;
    shared_encryption_key: {
        encrypted_key: string;
        device_id: string;
    };
}

const Shared: React.FC = () => {
    const [sharedVideos, setSharedVideos] = useState<SharedVideoData[]>([]);
    const [, setReceivedVideos] = useState<SharedVideoData[]>([]);
    const [receivedStreams, setReceivedStreams] = useState<SharedStreamData[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState<boolean>(true);

    const fetchVideosAndStreams = async () => {
        try {
            const token = sessionManager.getAccessToken();
            if (!token) {
                setError("Authentification requise. Veuillez vous connecter.");
                setLoading(false);
                return;
            }

            const currentDeviceId = localStorage.getItem("deviceId");
            if (!currentDeviceId) {
                setError("ID de l'appareil non trouvé. Veuillez vous reconnecter.");
                setLoading(false);
                return;
            }

            const res = await fetch(`/api/dashcam/v0/shared/videos/${currentDeviceId}`, {
                method: "GET",
                headers: { "X-CSRF-Access-Token": token }
            });
            if (!res.ok) throw new Error("Erreur lors du chargement des vidéos partagées");
            const rawData = await res.json();

            console.log("Raw data from API:", rawData);
            const userRole = sessionStorage.getItem("role");

            if (userRole === "TRUSTED") {
                setReceivedVideos(rawData);
            } else {
                setSharedVideos(rawData);
            }

            // Streams reçus par l'utilisateur
            const recipientStreamRes = await fetch("/api/dashcam/v0/shared/streams", {
                method: "GET",
                headers: { "X-CSRF-Access-Token": token }
            });
            if (!recipientStreamRes.ok) throw new Error("Erreur lors du chargement des streams reçus");
            const recipientStreamData = await recipientStreamRes.json();

            // Filtrer également les streams pour le device actuel
            const filteredStreams = recipientStreamData.filter(stream =>
                stream.shared_encryption_key &&
                stream.shared_encryption_key.some(key => key.device_id === currentDeviceId)
            );
            setReceivedStreams(filteredStreams);

        } catch (err) {
            if (err instanceof Error) {
                setError("Erreur lors du chargement des vidéos ou streams partagés ou reçus.");
                console.log(err.message);
            }
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchVideosAndStreams();
    }, []);

    if (loading) {
        return <section className="shared">Chargement des vidéos partagées...</section>;
    }

    if (error) {
        return <section className="shared">Erreur: {error}</section>;
    }

    return (
        <section className="shared">
            <section className="videos">
                <h1>LAST MOMENTS</h1>
                <section className="videos-content">
                    {sharedVideos.length > 0 ? (
                        sharedVideos.map((sharedVideo) => (
                            <SharedVideo
                                key={sharedVideo.id}
                                title={sharedVideo.video_id}
                                date={new Date(sharedVideo.shared_at).toLocaleDateString("fr-FR")}
                                size={"?"}
                                shared={[]}
                                encryptKey={sharedVideo.shared_encryption_key}
                            />
                        ))
                    ) : (
                        <p>Aucune vidéo partagée en tant que propriétaire.</p>
                    )}
                </section>
            </section>

            <section className="streams">
                <h1>STREAMS</h1>
                <section className="streams-content">
                    {receivedStreams.length > 0 ? (
                        receivedStreams.map((stream) => (
                            <Stream
                                key={stream.id}
                                title={stream.stream_id}
                                date={new Date(stream.shared_at).toLocaleDateString("fr-FR")}
                                shared={[]}
                            />
                        ))
                    ) : (
                        <p>Aucun stream reçu.</p>
                    )}
                </section>
            </section>
        </section>
    );
};

export default Shared;
import React, { useState, useEffect, useRef } from 'react';
import { decryptWebRTCFrame } from "../scripts/CryptoOperations.tsx";
import sessionManager from "../../components/sessionManager.tsx";

interface LiveStreamViewerProps {
    apiBaseUrl?: string;
}

// Interface pour RTCRtpReceiver avec createEncodedStreams
declare global {
    interface RTCRtpReceiver {
        createEncodedStreams?: () => {
            readable: ReadableStream<any>;
            writable: WritableStream<any>;
        };
        createEncodedVideoStreams?: () => {
            readable: ReadableStream<any>;
            writable: WritableStream<any>;
        };
    }
}

const WatchStream: React.FC<LiveStreamViewerProps> = () => {
    const [connectionId, setConnectionId] = useState<string>('');
    const [isConnected, setIsConnected] = useState<boolean>(false);
    const [availableStreams, setAvailableStreams] = useState<any[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [cryptoKey, setCryptoKey] = useState<Uint8Array | null>(null);

    const peerConnectionRef = useRef<RTCPeerConnection | null>(null);
    const videoRef = useRef<HTMLVideoElement>(null);
    const observerIdRef = useRef<string | null>(null);
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const videoContextRef = useRef<CanvasRenderingContext2D | null>(null);
    const decoderRef = useRef<number | null>(null);
    const streamRef = useRef<MediaStream | null>(null);
    const encodedFrameReaderRef = useRef<ReadableStreamDefaultReader<any> | null>(null);

    // Récupérer la liste des streams disponibles
    const fetchAvailableStreams = async () => {
        try {
            const response = await fetch("/api/dashcam/v0/streams", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
            });

            const data = await response.json();
            setAvailableStreams(data.active_streams || []);
        } catch (err) {
            console.error("Erreur lors de la récupération des streams:", err);
            setError("Impossible de récupérer la liste des streams");
        }
    };

    useEffect(() => {
        if (canvasRef.current) {
            canvasRef.current.width = 640;
            canvasRef.current.height = 480;
            videoContextRef.current = canvasRef.current.getContext('2d');
        }

        fetchAvailableStreams();
        const interval = setInterval(fetchAvailableStreams, 10000);

        return () => {
            clearInterval(interval);
            disconnectFromStream();
        };
    }, []);


    const handleIceCandidate = (event: RTCPeerConnectionIceEvent) => {
        if (event.candidate && observerIdRef.current) {
            fetch(`/api/dashcam/v0/webrtc/observer/ice_candidate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
                body: JSON.stringify({
                    connection_id: connectionId,
                    observer_id: observerIdRef.current,
                    candidate: {
                        sdpMLineIndex: event.candidate.sdpMLineIndex,
                        sdpMid: event.candidate.sdpMid,
                        sdp: event.candidate.candidate
                    }
                })
            }).catch(err => {
                console.error("Erreur lors de l'envoi du candidat ICE:", err);
            });
        }
    };

    // Traiter un frame WebRTC chiffré
    const processEncryptedFrame = async (encodedFrame: any) => {
        if (!cryptoKey) return;

        try {
            const buffer = new Uint8Array(encodedFrame.data);

            // Utiliser decryptWebRTCFrame de CryptoOperations
            const decryptedBuffer = await decryptWebRTCFrame(buffer, cryptoKey);

            if (decryptedBuffer && videoContextRef.current && canvasRef.current) {
                // Convertir les données déchiffrées en ImageData
                const width = canvasRef.current.width;
                const height = canvasRef.current.height;
                const pixelData = new Uint8ClampedArray(decryptedBuffer);

                // Vérifier la taille des données
                if (pixelData.length !== width * height * 4) {
                    console.error(`Taille des données déchiffrées incorrecte: ${pixelData.length}, attendu: ${width * height * 4}`);
                    return;
                }

                const imageData = new ImageData(pixelData, width, height);
                videoContextRef.current.putImageData(imageData, 0, 0);

                // Afficher le canvas déchiffré comme source vidéo
                if (!streamRef.current) {
                    streamRef.current = canvasRef.current.captureStream(30);
                    if (videoRef.current) {
                        videoRef.current.srcObject = streamRef.current;
                    }
                }
            }
        } catch (error) {
            console.error("Erreur de traitement de frame:", error);
        }
    };

    // Nettoyer les ressources
    const cleanupResources = () => {
        if (decoderRef.current) {
            clearInterval(decoderRef.current);
            decoderRef.current = null;
        }

        if (encodedFrameReaderRef.current) {
            encodedFrameReaderRef.current.cancel();
            encodedFrameReaderRef.current = null;
        }
    };

    // Déconnecter du stream
    const disconnectFromStream = () => {
        cleanupResources();

        if (peerConnectionRef.current) {
            peerConnectionRef.current.close();
            peerConnectionRef.current = null;
        }

        if (videoRef.current) {
            videoRef.current.srcObject = null;
        }

        streamRef.current = null;
        observerIdRef.current = null;
        setIsConnected(false);
    };

    // Se connecter via WebRTC
    const connectToStream = async () => {
        if (!connectionId.trim()) {
            setError("Veuillez entrer un ID de connexion valide");
            return;
        }

        setIsLoading(true);
        setError(null);
        setCryptoKey(null);  // TO DO : METTRE LA BONNE CLE ICI IMPORTANT
        disconnectFromStream();

        try {
            // Vérifier que le stream existe
            const streamResponse = await fetch("/api/dashcam/v0/streams", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
            });

            const streamData = await streamResponse.json();
            const streamExists = streamData.active_streams.some(
                (stream: any) => stream.id === connectionId
            );

            if (!streamExists) {
                throw new Error("Le stream demandé n'existe pas");
            }

            // Créer une variable pour stocker la méthode originale avant de la modifier
            const originalAddTrack = RTCPeerConnection.prototype.addTrack;

            // Modifier la méthode addTrack pour capturer les pistes précocement
            RTCPeerConnection.prototype.addTrack = function(...args) {
                const sender = originalAddTrack.apply(this, args);

                // Écouter l'événement track manuellement
                this.addEventListener('track', (e) => {
                    if (e.track && e.track.kind === 'video') {
                        setTimeout(() => {
                            const receivers = this.getReceivers();
                            for (const receiver of receivers) {
                                if (receiver.track && receiver.track.kind === 'video') {
                                    try {
                                        // Vérifier si l'API est supportée
                                        const createEncodedMethod = receiver.createEncodedStreams || receiver.createEncodedVideoStreams;
                                        if (!createEncodedMethod) {
                                            console.error("API d'interception non supportée");
                                            continue;
                                        }

                                        // Créer les streams encodés
                                        const receiverStreams = createEncodedMethod.call(receiver);
                                        const readableStream = receiverStreams.readable;

                                        // Stocker le reader pour utilisation ultérieure
                                        if (encodedFrameReaderRef.current) {
                                            encodedFrameReaderRef.current.cancel();
                                        }
                                        encodedFrameReaderRef.current = readableStream.getReader();

                                        // Démarrer la lecture des frames
                                        if (decoderRef.current) clearInterval(decoderRef.current);
                                        decoderRef.current = window.setInterval(async () => {
                                            try {
                                                if (!encodedFrameReaderRef.current) return;
                                                const result = await encodedFrameReaderRef.current.read();
                                                if (result.done) return;
                                                await processEncryptedFrame(result.value);
                                            } catch (e) {
                                                console.error("Erreur de lecture:", e);
                                            }
                                        }, 1000/30);

                                        break; // Ne traiter qu'un seul récepteur
                                    } catch (e) {
                                        console.error("Échec de l'interception précoce:", e);
                                    }
                                }
                            }
                        }, 0);
                    }
                }, { once: false });

                return sender;
            };

            // Création de la connexion WebRTC
            const pc = new RTCPeerConnection({
                iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
            });

            // Configuration de l'offre avec extension cryptex
            const offer = await pc.createOffer({
                offerToReceiveVideo: true,
                offerToReceiveAudio: false
            });

            if (offer.sdp) {
                // Activer cryptex dans le SDP
                offer.sdp = offer.sdp.replace(/a=mid:0\r\n/g, 'a=mid:0\r\na=extmap:14 urn:ietf:params:rtp-hdrext:cryptex\r\n');
                offer.sdp = offer.sdp.replace('useinbandfec=1', 'useinbandfec=1; cryptex=1');
            }

            await pc.setLocalDescription(offer);

            // Configuration des événements standard
            pc.ontrack = (event) => {
                if (videoRef.current && event.streams?.[0]) {
                    videoRef.current.srcObject = event.streams[0];
                }
            };

            pc.onicecandidate = handleIceCandidate;
            pc.onconnectionstatechange = () => {
                if (pc.connectionState === 'connected') {
                    setIsConnected(true);
                    setIsLoading(false);
                } else if (['failed', 'disconnected', 'closed'].includes(pc.connectionState)) {
                    setIsConnected(false);
                    setIsLoading(false);
                    setError("La connexion au stream a été perdue");
                    cleanupResources();
                }
            };

            peerConnectionRef.current = pc;

            // Envoi de l'offre au serveur
            const webRtcResponse = await fetch(`/api/dashcam/v0/webrtc/watch/${connectionId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    sdp: pc.localDescription?.sdp,
                    type: pc.localDescription?.type
                })
            });

            const answerData = await webRtcResponse.json();
            if (answerData.error) throw new Error(answerData.error);

            observerIdRef.current = answerData.observer_id;

            await pc.setRemoteDescription(
                new RTCSessionDescription({
                    sdp: answerData.sdp,
                    type: answerData.type
                })
            );

        } catch (err) {
            console.error("Erreur de connexion:", err);
            setError(`Erreur de connexion: ${err instanceof Error ? err.message : 'Erreur inconnue'}`);
            setIsConnected(false);
            setIsLoading(false);
        } finally {
            // Restaurer le prototype original
            RTCPeerConnection.prototype.addTrack = originalAddTrack; // TODO: Check cette erreur si importante
        }
    };

    // Sélectionner un stream disponible
    const selectStream = (streamId: string) => {
        setConnectionId(streamId);
    };

    return (
        <div className="live-stream-viewer">
            <h2>Visualisation de Stream Chiffré en Direct (WebRTC)</h2>

            <div className="connection-panel">
                <div className="input-group">
                    <label htmlFor="connection-id">ID du Stream:</label>
                    <input
                        id="connection-id"
                        type="text"
                        value={connectionId}
                        onChange={(e) => setConnectionId(e.target.value)}
                        placeholder="Entrez l'ID du stream"
                        disabled={isConnected}
                    />
                </div>

                {!isConnected ? (
                    <button
                        onClick={connectToStream}
                        disabled={isLoading || !connectionId.trim()}
                    >
                        {isLoading ? "Connexion..." : "Se connecter"}
                    </button>
                ) : (
                    <button onClick={disconnectFromStream}>
                        Déconnecter
                    </button>
                )}
            </div>

            {error && <div className="error-message">{error}</div>}

            <div className="stream-container">
                {isConnected || isLoading ? (
                    <>
                        <video
                            ref={videoRef}
                            autoPlay
                            playsInline
                            muted
                            className="stream-view"
                        />
                        <canvas
                            ref={canvasRef}
                            width={640}
                            height={480}
                            style={{ display: 'none' }}
                        />
                    </>
                ) : (
                    <div className="no-stream">
                        {isLoading ? "Connexion en cours..." : "Aucun stream connecté"}
                    </div>
                )}
            </div>

            <div className="available-streams">
                <h3>Streams disponibles</h3>
                {availableStreams.length > 0 ? (
                    <ul>
                        {availableStreams.map((stream) => (
                            <li key={stream.id} onClick={() => selectStream(stream.id)}>
                                Stream ID: {stream.id}
                                <span className="stream-info">
                                    ({stream.buffer_frames} frames, {stream.observers} observateurs)
                                    {stream.has_webrtc ? " (WebRTC actif)" : " (Pas de WebRTC)"}
                                </span>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p>Aucun stream disponible</p>
                )}
                <button onClick={fetchAvailableStreams}>Rafraîchir</button>
            </div>
        </div>
    );
};

export default WatchStream;
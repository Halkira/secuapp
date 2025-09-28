import React, { useRef, useEffect, useState } from 'react';
import { generateRandomKey } from "../scripts/CryptoOperations";
import { useStreamingProcess } from "../hooks/useStreamingProcess";

const Stream: React.FC = () => {
    const cryptoKeyRef = useRef<Uint8Array | null>(null);
    const [showPopup, setShowPopup] = useState(false);
    const [recipientEmail, setRecipientEmail] = useState("");
    const [errorMessage, setErrorMessage] = useState("");

    useEffect(() => {
        const generateKey = async () => {
            cryptoKeyRef.current = await generateRandomKey();
        };
        generateKey();
    }, []);

    const FPS = 24;

    const {
        isStreaming,
        status,
        webrtcStatus,
        connectionId,
        videoRef,
        canvasRef,
        startStream,
        stopStream
    } = useStreamingProcess(cryptoKeyRef.current, FPS);

    const handleStartStream = () => {
        setShowPopup(true);
    };

    const handleShareStream = async () => {
        if (!recipientEmail) {
            setErrorMessage("Veuillez entrer un email valide.");
            return;
        }
        setShowPopup(false);
        try {
            await startStream(recipientEmail); // Passer l'email à startStream
        } catch (error) {
            console.error("Erreur lors du démarrage du streaming :", error);
            setErrorMessage("Une erreur est survenue lors du démarrage du streaming.");
        }
    };

    const handleIgnoreShare = async () => {
        setShowPopup(false);
        try {
            await startStream(); // Démarrer sans partage
        } catch (error) {
            console.error("Erreur lors du démarrage du streaming :", error);
            setErrorMessage("Une erreur est survenue lors du démarrage du streaming.");
        }
    };

    return (
        <div className="dashcam-app">
            <h1>Système DashCam Sécurisé</h1>
            <div className="video-container">
                <video
                    ref={videoRef}
                    autoPlay
                    muted
                    playsInline
                    className="video-preview"
                />
                <canvas
                    ref={canvasRef}
                    width={640}
                    height={480}
                    style={{ display: 'none' }}
                />
            </div>
            <div className="controls">
                {!isStreaming ? (
                    <button
                        onClick={handleStartStream}
                        disabled={isStreaming}
                        className="stream-button start-button"
                    >
                        Démarrer le streaming
                    </button>
                ) : (
                    <button
                        onClick={stopStream}
                        disabled={!isStreaming}
                        className="stream-button stop-button"
                    >
                        Arrêter le streaming
                    </button>
                )}
            </div>

            {showPopup && (
                <div className="popup">
                    <div className="popup-content">
                        <h2>Partager le stream</h2>
                        <p>Souhaitez-vous partager le stream ? Si oui, entrez l'email du destinataire :</p>
                        <input
                            type="email"
                            value={recipientEmail}
                            onChange={(e) => setRecipientEmail(e.target.value)}
                            placeholder="Email du destinataire"
                        />
                        <div className="popup-bottom">
                            <button onClick={handleShareStream}>Partager</button>
                            <button onClick={handleIgnoreShare}>Ignorer</button>
                        </div>
                        {errorMessage && <p className="error">{errorMessage}</p>}
                    </div>
                </div>
            )}

            <div className="status-panel">
                <div className="status-item">
                    <span className="status-label">Statut WebSocket:</span>
                    <span className="status-value">{status}</span>
                </div>
                <div className="status-item">
                    <span className="status-label">Statut WebRTC:</span>
                    <span className="status-value">{webrtcStatus}</span>
                </div>
                <div className="status-item">
                    <span className="status-label">Sécurité:</span>
                    <span className="status-value">Chiffrement AES-GCM activé</span>
                </div>
                {connectionId && (
                    <div className="status-item">
                        <span className="status-label">ID de connexion:</span>
                        <span className="status-value">{connectionId}</span>
                    </div>
                )}
            </div>
        </div>
    );
};

export default Stream;
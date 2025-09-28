import React, { useState, useRef, useEffect, useCallback } from "react";
import {GetProtectedPrivateKey} from "../scripts/KeyOperations";
import sessionManager from "../../components/sessionManager.tsx";
import {base64ToArrayBuffer} from "../../components/encoding.ts";
import {decryptWebRTCFrame} from "../scripts/CryptoOperations.tsx";

interface StreamProps {
    title: string;
    date: string;
    shared: string[];
    onDelete?: () => void;
}

const Stream: React.FC<StreamProps> = ({ title, date, shared, onDelete }) => {
    const [isPopupOpen, setIsPopupOpen] = useState(false);
    const [cryptoKey, setCryptoKey] = useState<CryptoKey | null>(null);
    const [isConnected, setIsConnected] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const videoRef = useRef<HTMLVideoElement>(null);
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const peerConnectionRef = useRef<RTCPeerConnection | null>(null);
    const encodedFrameReaderRef = useRef<ReadableStreamDefaultReader<any> | null>(null);
    const videoContextRef = useRef<CanvasRenderingContext2D | null>(null);

    // Initialiser le contexte du canvas
    useEffect(() => {
        if (canvasRef.current) {
            canvasRef.current.width = 640;
            canvasRef.current.height = 480;
            videoContextRef.current = canvasRef.current.getContext("2d");
        }
    }, []);

    // Fonction pour récupérer et déchiffrer la clé de stream
    const fetchAndDecryptStreamKey = async () => {
        try {
            const deviceId = localStorage.getItem("deviceId");
            const token = sessionManager.getAccessToken();
            if (!token || !deviceId) throw new Error("Authentification ou ID de l'appareil manquant.");

            const response = await fetch(`/api/dashcam/v0/shared/stream/${title}/key/${deviceId}`, {
                method: "GET",
                headers: { "X-CSRF-Access-Token": token },
            });

            if (!response.ok) throw new Error("Erreur lors de la récupération de la clé de stream.");
            const { encrypted_key: encryptedKeyBase64 } = await response.json();

            const encryptedKeyBuffer = base64ToArrayBuffer(encryptedKeyBase64);
            const privateKey = await GetProtectedPrivateKey();

            const decryptedStreamKeyBuffer = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                privateKey,
                encryptedKeyBuffer
            );

            const key = await window.crypto.subtle.importKey(
                "raw",
                decryptedStreamKeyBuffer,
                { name: "AES-GCM" },
                false,
                ["decrypt"]
            );

            setCryptoKey(key);
        } catch (err) {
            console.error("Erreur lors du déchiffrement de la clé de stream :", err);
            setError("Impossible de déchiffrer la clé de stream.");
        }
    };

    // Fonction pour traiter les frames WebRTC chiffrés
    const processEncryptedFrame = useCallback(
        async (encodedFrame: any) => {
            if (!cryptoKey || !videoContextRef.current || !canvasRef.current) return;

            try {
                const decryptedBuffer = await decryptWebRTCFrame(encodedFrame.data, new Uint8Array(), cryptoKey);

                if (decryptedBuffer) {
                    const width = canvasRef.current.width;
                    const height = canvasRef.current.height;
                    const pixelData = new Uint8ClampedArray(decryptedBuffer);

                    if (pixelData.length === width * height * 4) {
                        const imageData = new ImageData(pixelData, width, height);
                        videoContextRef.current.putImageData(imageData, 0, 0);
                    }
                }
            } catch (err) {
                console.error("Erreur lors du traitement des frames :", err);
            }
        },
        [cryptoKey]
    );

    // Fonction pour établir une connexion WebRTC
    const connectToStream = useCallback(async () => {
        setError(null);
        setIsConnected(false);

        try {
            const pc = new RTCPeerConnection({
                iceServers: [{ urls: "stun:stun.l.google.com:19302" }],
            });

            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    fetch(`/api/dashcam/v0/webrtc/observer/ice_candidate`, {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json",
                            "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                        },
                        body: JSON.stringify({
                            stream_id: title,
                            candidate: event.candidate,
                        }),
                    }).catch((err) => console.error("Erreur ICE :", err));
                }
            };

            pc.ontrack = (event) => {
                if (videoRef.current && event.streams[0]) {
                    videoRef.current.srcObject = event.streams[0];
                }
            };

            const offer = await pc.createOffer({
                offerToReceiveVideo: true,
                offerToReceiveAudio: false,
            });

            await pc.setLocalDescription(offer);

            const response = await fetch(`/api/dashcam/v0/webrtc/watch/${title}`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
                body: JSON.stringify({
                    sdp: pc.localDescription?.sdp,
                    type: pc.localDescription?.type,
                }),
            });

            const { sdp, type } = await response.json();
            await pc.setRemoteDescription(new RTCSessionDescription({ sdp, type }));

            pc.getReceivers().forEach((receiver) => {
                if (receiver.track.kind === "video" && receiver.createEncodedStreams) {
                    const { readable } = receiver.createEncodedStreams();
                    encodedFrameReaderRef.current = readable.getReader();

                    const readFrames = async () => {
                        while (true) {
                            const { value, done } = await encodedFrameReaderRef.current.read();
                            if (done) break;
                            await processEncryptedFrame(value);
                        }
                    };

                    readFrames().catch((err) => console.error("Erreur de lecture des frames :", err));
                }
            });

            peerConnectionRef.current = pc;
            setIsConnected(true);
        } catch (err) {
            console.error("Erreur de connexion WebRTC :", err);
            setError("Impossible de se connecter au stream.");
        }
    }, [title, processEncryptedFrame]);

    // Fonction pour fermer le popup
    const handleClosePopup = () => {
        setIsPopupOpen(false);
        if (peerConnectionRef.current) {
            peerConnectionRef.current.close();
            peerConnectionRef.current = null;
        }
        if (encodedFrameReaderRef.current) {
            encodedFrameReaderRef.current.cancel();
            encodedFrameReaderRef.current = null;
        }
        setIsConnected(false);
    };

    // Fonction pour ouvrir le popup et initialiser le stream
    const handleWatchStream = async () => {
        await fetchAndDecryptStreamKey();
        setIsPopupOpen(true);
        connectToStream();
    };


    // const handleWatchStream = async () => {
    //     const deviceId = localStorage.getItem("deviceId");
    //     const token = sessionManager.getAccessToken();
    //     if(token){
    //         const response = await fetch(`/api/dashcam/v0/shared/stream/${title}/key/${deviceId}`, {
    //             method: "GET",
    //             headers: { "X-CSRF-Access-Token": token }
    //         })
    //
    //         const encryptedKeyBase64 = await response.json();
    //
    //         //TO DO DECHIFFRER CLE
    //
    //         const encryptedKeyBuffer = base64ToArrayBuffer(encryptedKeyBase64);
    //
    //         const privateKey = await GetProtectedPrivateKey();
    //
    //         try {
    //             const decryptedStreamKeyBuffer = await window.crypto.subtle.decrypt(
    //                 {
    //                     name: "RSA-OAEP",
    //                 },
    //                 privateKey,
    //                 encryptedKeyBuffer
    //             );
    //
    //             //decryptedStreamKeyBase64 = arrayBufferToBase64(decryptedStreamKeyBuffer);
    //
    //         } catch (specificError) {
    //             console.error("Error decrypting shared key with RSA-OAEP:", specificError);
    //             throw specificError;
    //         }
    //     }
    // };  PREVIOUS ONE WITH LVCA


    return (
        <section className="stream">
            <h2>{title}</h2>
            <p>Date : {date}</p>
            <p>Shared by : {shared.join(", ")}</p>
            <button onClick={handleWatchStream}>WATCH</button>
            {onDelete && (
                <button onClick={onDelete} className="delete-button">Delete</button>
            )}
            {isPopupOpen && (
                <div className="popup">
                    <div className="popup-content">
                        <button onClick={handleClosePopup} className="close-button">X</button>
                        {error && <p className="error">{error}</p>}
                        <div className="stream-container">
                            <video ref={videoRef} autoPlay playsInline muted className="stream-video" />
                            <canvas ref={canvasRef} style={{ display: "none" }} />
                        </div>
                        {!isConnected && <p>Connexion au stream...</p>}
                    </div>
                </div>
            )}
        </section>
    );
};

export default Stream;
import { useState, useRef, useCallback, useEffect } from 'react';
import { CryptoOperation } from "../scripts/CryptoOperations";
import { useWebSocket } from './useWebSocket';
import { useWebRTC } from './useWebRTC';
import { useWebcam } from './useWebcam';
import KeyOperations from "../scripts/KeyOperations.tsx";
import { useMyContext } from "../../components/MasterKeyContext.tsx";
import {arrayBufferToBase64, base64ToArrayBuffer} from "../../components/encoding.ts";
import sessionManager from "../../components/sessionManager.tsx";

interface StreamingHookReturn {
    isStreaming: boolean;
    status: string;
    webrtcStatus: string;
    connectionId: string | null;
    videoRef: React.RefObject<HTMLVideoElement>;
    canvasRef: React.RefObject<HTMLCanvasElement>;
    startStream: (recipientEmail?: string) => Promise<void>;
    stopStream: () => void;
}

export function useStreamingProcess(cryptoKey: Uint8Array, fps: number = 24): StreamingHookReturn {
    const [isStreaming, setIsStreaming] = useState(false);
    const [status, setStatus] = useState('');
    const [, setRecipientEmail] = useState<string | undefined>(undefined);
    const frameIntervalRef = useRef<number | null>(null);
    const { mk } = useMyContext();

    const { setupWebRTC, closeWebRTC, webrtcStatus, rtcSenderRef } = useWebRTC();

    const fetchPublicKey = async (email: string) => {
        try {
            const response = await fetch(`/api/dashcam/v0/dev/user/pubkey/${email}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Access-Token': sessionManager.getAccessToken() || '',
                },
            });

            if (!response.ok) {
                throw new Error(`Erreur HTTP: ${response.status}`);
            }

            const data = await response.json();
            return data.pubkey_list || [];
        } catch (err) {
            console.error('Erreur lors de la récupération de la clé publique:', err);
            throw err;
        }
    };

    const encryptWithPublicKeys = async (keyToEncrypt: string, publicKeysList: [string, string][]) => {
        try {
            const encryptedKeysWithDevices = [];

            for (const [deviceId, pubKey] of publicKeysList) {
                const publicKeyObj = await crypto.subtle.importKey(
                    'spki',
                    Uint8Array.from(atob(pubKey), c => c.charCodeAt(0)).buffer,
                    {
                        name: 'RSA-OAEP',
                        hash: 'SHA-256',
                    },
                    false,
                    ['encrypt']
                );

                const encryptedKey = await crypto.subtle.encrypt(
                    {
                        name: 'RSA-OAEP'
                    },
                    publicKeyObj,
                    base64ToArrayBuffer(keyToEncrypt)
                );

                encryptedKeysWithDevices.push({
                    encrypted_key: arrayBufferToBase64(encryptedKey),
                    device_id: deviceId
                });
            }

            return encryptedKeysWithDevices;
        } catch (error) {
            console.error("Erreur lors du chiffrement avec les clés publiques:", error);
            throw error;
        }
    };

    const handleConnectionIdReceived = useCallback(async (id: string, email?: string) => {
        if (streamRef.current) {
            setupWebRTC(id, streamRef.current, cryptoKey);

            if (email) {
                try {
                    setStatus("Récupération des clés publiques du destinataire...");
                    const publicKeysList = await fetchPublicKey(email);
                    if (!publicKeysList || publicKeysList.length === 0) {
                        throw new Error("Aucune clé publique trouvée pour cet utilisateur.");
                    }

                    const encryptedStreamKeysWithDevices = await encryptWithPublicKeys(arrayBufferToBase64(cryptoKey), publicKeysList);

                    const response = await fetch(`/api/dashcam/v0/share/stream`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Access-Token': sessionManager.getAccessToken() || "",
                        },
                        body: JSON.stringify({
                            stream_id: id,
                            recipient_email: email,
                            shared_encryption_key: encryptedStreamKeysWithDevices,
                        }),
                    });

                    console.log("Connection id : ", id, "Email : ", email, "Shared enc key list : ", encryptedStreamKeysWithDevices)

                    if (!response.ok) {
                        const errorData = await response.json();
                        throw new Error(errorData.detail || `Erreur HTTP: ${response.status}`);
                    }

                    setStatus("Stream partagé avec succès !");
                } catch (error) {
                    if (error instanceof Error) {
                        console.error("Erreur lors du partage du stream :", error);
                        setStatus(`Échec du partage : ${error.message}`);
                    }
                }
            }
        }
    }, [setupWebRTC, cryptoKey]);

    const {
        isConnected,
        connectionId,
        connectWebSocket,
        disconnectWebSocket,
        wsRef
    } = useWebSocket(handleConnectionIdReceived);

    const {
        streamRef,
        videoRef,
        canvasRef,
        startWebcam,
        stopWebcam,
        captureFrame,
        setupWebcamDisconnectionListener
    } = useWebcam();

    // Gérer la déconnexion de la webcam
    const handleWebcamDisconnection = useCallback(() => {
        setStatus('Webcam déconnectée, arrêt des connexions...');

        // 1. Fermer d'abord le WebSocket
        disconnectWebSocket();

        // 2. Attendre un court instant puis fermer WebRTC
        setTimeout(() => {
            closeWebRTC();

            // 3. Arrêter le streaming
            if (frameIntervalRef.current) {
                clearInterval(frameIntervalRef.current);
                frameIntervalRef.current = null;
            }

            stopWebcam();

            setIsStreaming(false);
            setStatus('Streaming arrêté (webcam déconnectée)');
        }, 100);
    }, [disconnectWebSocket, closeWebRTC, stopWebcam]);

    // Fonction pour capturer et envoyer un frame
    const captureAndSendFrame = useCallback(async () => {
        if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;

        const imageDataUrl = captureFrame();
        if (!imageDataUrl) return;

        try {
            const { data: encryptedData, iv } = await CryptoOperation(imageDataUrl, cryptoKey, true);

            // Concaténer IV et données chiffrées
            const combined = new Uint8Array(iv!.length + (encryptedData as ArrayBuffer).byteLength);
            combined.set(iv!, 0);
            combined.set(new Uint8Array(encryptedData as ArrayBuffer), iv!.length);

            const encryptedBase64 = arrayBufferToBase64(combined.buffer);
            wsRef.current.send(encryptedBase64);
        } catch (error) {
            console.error(error);
        }
    }, [wsRef, captureFrame, cryptoKey]);

    // Configuration de l'intercepteur WebRTC pour chiffrer les frames
    const setupWebRTCEncryption = useCallback(() => {
        if (!rtcSenderRef.current || !('createEncodedStreams' in RTCRtpSender.prototype)) {
            console.warn('API d\'encodage WebRTC non disponible, le chiffrement ne sera pas appliqué');
            return;
        }

        try {
            // Obtenir les flux encodés
            const senderStreams = rtcSenderRef.current.createEncodedStreams();
            const readableStream = senderStreams.readable;
            const writableStream = senderStreams.writable;

            // Transformer pour chiffrer chaque frame
            const transformStream = new TransformStream({
                async transform(frame, controller) {
                    try {
                        const frameData = new Uint8Array(frame.data);

                        const { data: encryptedContent } = await CryptoOperation(
                            frameData.buffer,
                            cryptoKey,
                            true
                        );

                        frame.data = encryptedContent as ArrayBuffer;
                        controller.enqueue(frame);
                    } catch (error) {
                        console.error(error);
                        controller.enqueue(frame);
                    }
                }
            });

            readableStream
                .pipeThrough(transformStream)
                .pipeTo(writableStream)
                .catch((err: Error) => console.error(err));

        } catch (error) {
            console.error(error);
        }
    }, [rtcSenderRef, cryptoKey]);

    // Démarrer l'envoi périodique des frames
    const startSendingFrames = useCallback(() => {
        if (frameIntervalRef.current) {
            clearInterval(frameIntervalRef.current);
        }

        frameIntervalRef.current = window.setInterval(() => {
            captureAndSendFrame();
        }, 1000 / fps);
    }, [captureAndSendFrame, fps]);


    const startStream = useCallback(async (recipientEmail?: string) => {
        if(recipientEmail) {
            setRecipientEmail(recipientEmail);
            console.log("Recipient email is on memory",  recipientEmail);
        }

        setStatus("Récupération de la master key...");

        let masterKeyEncrypted = mk;
        if(!mk){
            masterKeyEncrypted = await KeyOperations.GetMasterKey();
        }

        if (!masterKeyEncrypted) {
            setStatus("Impossible de récupérer la master key");
            return;
        }

        const masterKey = await KeyOperations.UnlockMasterKey(masterKeyEncrypted);
        if (!masterKey) {
            return console.error("Problem in UnlockMaster key!");
        }

        // 2. Chiffrement de la clé de stream (cryptoKey) avec la masterkey
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedStreamKeyBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            masterKey,
            cryptoKey
        );

        // 3. Concaténation IV + données chiffrées, puis base64
        const combined = new Uint8Array(iv.length + encryptedStreamKeyBuffer.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encryptedStreamKeyBuffer), iv.length);
        const encryptedStreamKeyAndIvBase64 = arrayBufferToBase64(combined.buffer);

        try {
            const webcamStarted = await startWebcam();

            if (!webcamStarted) {
                setStatus('Impossible d\'accéder à la webcam');
                return;
            }
            setupWebcamDisconnectionListener(handleWebcamDisconnection);
            if (!isConnected) {
                connectWebSocket(encryptedStreamKeyAndIvBase64, recipientEmail);
            }

            setIsStreaming(true);
            setStatus('Streaming en cours (chiffré)...');

            startSendingFrames();

            // Configurer le chiffrement WebRTC après un court délai, pour s'assurer que la connexion est établie
            setTimeout(() => {
                if (rtcSenderRef.current) {
                    setupWebRTCEncryption();
                }
            }, 1000);

        } catch (error) {
            console.error(error);
            setStatus('Erreur lors du démarrage du streaming');
        }
    }, [
        startWebcam,
        setupWebcamDisconnectionListener,
        handleWebcamDisconnection,
        isConnected,
        connectWebSocket,
        startSendingFrames,
        setupWebRTCEncryption,
    ]);

    const stopStream = useCallback(() => {
        // Arrêter l'envoi des frames
        if (frameIntervalRef.current) {
            clearInterval(frameIntervalRef.current);
            frameIntervalRef.current = null;
        }

        stopWebcam();
        closeWebRTC();
        disconnectWebSocket();
        setIsStreaming(false);
        setStatus('Streaming arrêté');
    }, [stopWebcam, closeWebRTC, disconnectWebSocket]);

    // Nettoyage lors du démontage du composant
    useEffect(() => {
        return () => {
            stopStream();
        };
    }, [stopStream]);

    return {
        isStreaming,
        status,
        webrtcStatus,
        connectionId,
        videoRef,
        canvasRef,
        startStream,
        stopStream
    };
}
import { useState, useRef, useCallback } from 'react';
import sessionManager from "../../components/sessionManager.tsx";

interface WebRTCHookReturn {
    webrtcStatus: string;
    setupWebRTC: (streamId: string, stream: MediaStream, cryptoKey?: Uint8Array) => Promise<void>;
    closeWebRTC: () => void;
    peerConnectionRef: React.MutableRefObject<RTCPeerConnection | null>;
    rtcSenderRef: React.MutableRefObject<RTCRtpSender | null>;
}

export function useWebRTC(): WebRTCHookReturn {
    const [webrtcStatus, setWebrtcStatus] = useState('');
    const peerConnectionRef = useRef<RTCPeerConnection | null>(null);
    const rtcSenderRef = useRef<RTCRtpSender | null>(null);

    const setupWebRTC = useCallback(async (streamId: string, mediaStream: MediaStream, cryptoKey?: Uint8Array) => {
        try {
            // Fermer une éventuelle connexion existante
            if (peerConnectionRef.current) {
                peerConnectionRef.current.close();
            }

            const pc = new RTCPeerConnection({
                iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
            });

            peerConnectionRef.current = pc;

            // Ajouter les pistes audio/vidéo au peer connection
            // Stockage du sender pour le chiffrement ultérieur
            mediaStream.getTracks().forEach(track => {
                const sender = pc.addTrack(track, mediaStream);
                if (track.kind === 'video') {
                    rtcSenderRef.current = sender;
                }
            });

            // Gérer les candidats ICE
            pc.onicecandidate = ({ candidate }) => {
                if (candidate) {
                    fetch('/api/dashcam/v0/webrtc/ice_candidate', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                        },
                        body: JSON.stringify({
                            connection_id: streamId,
                            candidate: {
                                sdpMLineIndex: candidate.sdpMLineIndex,
                                sdpMid: candidate.sdpMid,
                                candidate: candidate.candidate
                            }
                        })
                    }).catch(err => {
                        console.error(err);
                    });
                }
            };

            pc.onconnectionstatechange = () => {
                setWebrtcStatus(`État WebRTC: ${pc.connectionState}`);
            };

            const offer = await pc.createOffer();

            // Si la clé de chiffrement est fournie, modifier le SDP pour indiquer l'usage du chiffrement
            if (offer.sdp && cryptoKey) {
                offer.sdp = offer.sdp.replace('useinbandfec=1', 'useinbandfec=1;cryptex=1');
            }

            await pc.setLocalDescription(offer);

            // Envoyer l'offre au serveur
            const response = await fetch('/api/dashcam/v0/webrtc/offer', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
                body: JSON.stringify({
                    sdp: pc.localDescription?.sdp,
                    type: pc.localDescription?.type,
                    connection_id: streamId
                })
            });

            const answerData = await response.json();

            if (answerData.error) {
                throw new Error(answerData.error);
            }

            await pc.setRemoteDescription(new RTCSessionDescription({
                sdp: answerData.sdp,
                type: answerData.type
            }));

            setWebrtcStatus("WebRTC connecté");

        } catch (error) {
            console.error(error);
            setWebrtcStatus(`Erreur WebRTC: ${error instanceof Error ? error.message : 'Erreur inconnue'}`);
        }
    }, []);

    const closeWebRTC = useCallback(() => {
        if (peerConnectionRef.current) {
            peerConnectionRef.current.close();
            peerConnectionRef.current = null;
            rtcSenderRef.current = null;
        }
    }, []);

    return {
        webrtcStatus,
        setupWebRTC,
        closeWebRTC,
        peerConnectionRef,
        rtcSenderRef
    };
}
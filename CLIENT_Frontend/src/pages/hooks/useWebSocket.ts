import { useState, useRef, useCallback } from 'react';
import sessionManager from "../../components/sessionManager.tsx";

interface WebSocketHookReturn {
    isConnected: boolean;
    connectionId: string | null;
    status: string;
    connectWebSocket: (encryptedStreamKeyAndIvBase64: string, recipientEmail?: string) => void;
    disconnectWebSocket: () => void;
    wsRef: React.MutableRefObject<WebSocket | null>;
}

export function useWebSocket(
    onConnectionIdReceived: (id: string, recipientEmail?: string) => void,
): WebSocketHookReturn {
    const [isConnected, setIsConnected] = useState(false);
    const [connectionId, setConnectionId] = useState<string | null>(null);
    const [status, setStatus] = useState('');
    const wsRef = useRef<WebSocket | null>(null);

    const sendEncryptedStreamKeyAndIvBase64ToBackend = useCallback(async (streamId: string, encryptedStreamKeyAndIvBase64: string) => {
        try {
            await fetch('/api/dashcam/v0/dev/stream/key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Access-Token': sessionManager.getAccessToken() || '',
                },
                body: JSON.stringify({
                    encrypted_key: encryptedStreamKeyAndIvBase64,
                    stream_id: streamId,
                }),
            });
        } catch (error) {
            console.error(error);
        }
    }, []);

    const connectWebSocket = useCallback((encryptedStreamKeyAndIvBase64: string, recipientEmail?: string) => {
        const accessToken = sessionManager.getAccessToken();
        const protocol = window.location.protocol === "https:" ? "wss" : "ws";
        const wsUrl = new URL(`${protocol}://${window.location.host}/api/dashcam/v0/ws/stream`);

        if (accessToken) {
            wsUrl.searchParams.append('csrf_token', accessToken);
        }

        const ws = new WebSocket(wsUrl.toString());

        ws.onopen = () => {
            setIsConnected(true);
            setStatus('Connecté au serveur WebSocket');
            wsRef.current = ws;
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.connection_id) {
                    setConnectionId(data.connection_id);
                    onConnectionIdReceived(data.connection_id, recipientEmail);
                    sendEncryptedStreamKeyAndIvBase64ToBackend(data.connection_id, encryptedStreamKeyAndIvBase64);
                    if(recipientEmail){
                        console.log("FAKING SHARE STREAM");
                    }
                }
            } catch (e) {
                console.error(e);
            }
        };

        ws.onclose = () => {
            setIsConnected(false);
            setStatus('Déconnecté du serveur WebSocket');
            wsRef.current = null;
        };

        ws.onerror = (error) => {
            console.error(error);
            setStatus('Erreur de connexion WebSocket');
        };
    }, [onConnectionIdReceived, sendEncryptedStreamKeyAndIvBase64ToBackend]);

    const disconnectWebSocket = useCallback(() => {
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
            wsRef.current.close();
        }
    }, []);

    return {
        isConnected,
        connectionId,
        status,
        connectWebSocket,
        disconnectWebSocket,
        wsRef
    };
}
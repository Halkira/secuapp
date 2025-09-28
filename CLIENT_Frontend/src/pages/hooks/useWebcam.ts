// CLIENT_Frontend/src/pages/hooks/useWebcam.ts
import { useRef, useCallback, useEffect } from 'react';

interface WebcamHookReturn {
    streamRef: React.MutableRefObject<MediaStream | null>;
    videoRef: React.RefObject<HTMLVideoElement>;
    canvasRef: React.RefObject<HTMLCanvasElement>;
    startWebcam: () => Promise<boolean>;
    stopWebcam: () => void;
    captureFrame: () => string | null;
    setupWebcamDisconnectionListener: (onDisconnect: () => void) => () => void;
}

export function useWebcam(): WebcamHookReturn {
    const streamRef = useRef<MediaStream | null>(null);
    const videoRef = useRef<HTMLVideoElement>(null);
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const checkIntervalRef = useRef<number | null>(null);

    const startWebcam = useCallback(async (): Promise<boolean> => {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({
                video: { width: 640, height: 480 },
                audio: true
            });

            streamRef.current = stream;

            if (videoRef.current) {
                videoRef.current.srcObject = stream;
            }

            return true;
        } catch (error) {
            console.error(error);
            return false;
        }
    }, []);

    const stopWebcam = useCallback(() => {
        if (streamRef.current) {
            streamRef.current.getTracks().forEach(track => track.stop());
            streamRef.current = null;
        }

        if (videoRef.current) {
            videoRef.current.srcObject = null;
        }

        if (checkIntervalRef.current) {
            clearInterval(checkIntervalRef.current);
            checkIntervalRef.current = null;
        }
    }, []);

    const captureFrame = useCallback((): string | null => {
        if (!canvasRef.current || !videoRef.current) return null;

        const context = canvasRef.current.getContext('2d');
        if (!context) return null;

        context.drawImage(videoRef.current, 0, 0, canvasRef.current.width, canvasRef.current.height);
        return canvasRef.current.toDataURL('image/jpeg', 0.7);
    }, []);

    const setupWebcamDisconnectionListener = useCallback((onDisconnect: () => void) => {
        if (!streamRef.current) return () => {};

        const tracks = streamRef.current.getVideoTracks();

        // Configurer les écouteurs d'événements pour chaque piste
        tracks.forEach(track => {
            track.onended = () => {
                onDisconnect();
            };
        });

        // Vérifier périodiquement l'état des pistes
        checkIntervalRef.current = window.setInterval(() => {
            if (!streamRef.current) return;

            const allTracksEnded = streamRef.current.getVideoTracks().every(
                track => !track.enabled || track.readyState === 'ended'
            );

            if (allTracksEnded) {
                onDisconnect();
            }
        }, 500);

        // Fonction de nettoyage
        return () => {
            if (checkIntervalRef.current) {
                clearInterval(checkIntervalRef.current);
                checkIntervalRef.current = null;
            }
        };
    }, []);

    // Nettoyage au démontage du composant
    useEffect(() => {
        return () => {
            stopWebcam();
        };
    }, [stopWebcam]);

    return {
        streamRef,
        videoRef,
        canvasRef,
        startWebcam,
        stopWebcam,
        captureFrame,
        setupWebcamDisconnectionListener
    };
}
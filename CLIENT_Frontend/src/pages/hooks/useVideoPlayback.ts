// CLIENT_Frontend/src/pages/hooks/useVideoPlayback.ts
import { useState, useRef } from 'react';

export function useVideoPlayback(FPS: number = 24) {
    const [isPlaying, setIsPlaying] = useState<boolean>(false);
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const animationRef = useRef<number | null>(null);

    const playDecodedFrames = (decodedFrames: string[]) => {
        if (!decodedFrames.length || !canvasRef.current) {
            return console.error('Aucune frame déchiffrée ou canvas introuvable');

        }

        if (animationRef.current) {
            cancelAnimationFrame(animationRef.current);
        }

        const canvas = canvasRef.current;
        const context = canvas.getContext('2d');
        if (!context) {
            return console.error('Impossible de récupérer le contexte 2D du canvas');
        }

        setIsPlaying(true);

        let frameIndex = 0;
        const interval = 1000 / FPS;
        let lastTime = 0;

        const drawFrame = (timestamp: number) => {
            if (!isPlaying) return;

            const elapsed = timestamp - lastTime;

            if (elapsed > interval) {
                const img = new Image();
                img.onload = () => {
                    context.clearRect(0, 0, canvas.width, canvas.height);
                    context.drawImage(img, 0, 0, canvas.width, canvas.height);
                };
                img.onerror = () => {
                    console.error('Erreur lors du chargement de la frame:', decodedFrames[frameIndex]);
                };
                img.src = decodedFrames[frameIndex];
                frameIndex = (frameIndex + 1) % decodedFrames.length;
                lastTime = timestamp;
            }

            animationRef.current = requestAnimationFrame(drawFrame);
        };

        animationRef.current = requestAnimationFrame(drawFrame);
    };

    const stopPlayback = () => {
        setIsPlaying(false);
        if (animationRef.current) {
            cancelAnimationFrame(animationRef.current);
            animationRef.current = null;
        }
    };

    return {
        isPlaying,
        canvasRef,
        playDecodedFrames,
        stopPlayback
    };
}
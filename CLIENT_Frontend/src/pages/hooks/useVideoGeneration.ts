// CLIENT_Frontend/src/pages/hooks/useVideoGeneration.ts
import { useState, useRef } from 'react';

export function useVideoGeneration(FPS: number = 24) {
    const [isGeneratingVideo, setIsGeneratingVideo] = useState<boolean>(false);
    const [videoProgress, setVideoProgress] = useState<number>(0);
    const [videoURL, setVideoURL] = useState<string | null>(null);
    const videoRef = useRef<HTMLVideoElement>(null);
    const mediaRecorderRef = useRef<MediaRecorder | null>(null);
    const chunksRef = useRef<BlobPart[]>([]);
    const [error, setError] = useState<string | null>(null);

    const generateVideo = async (decodedFrames: string[]) => {
        if (!decodedFrames.length) {
            setError("Aucune image déchiffrée disponible");
            return;
        }

        setIsGeneratingVideo(true);
        setVideoProgress(0);
        setVideoURL(null);

        try {
            // Créer un canvas pour le rendu des frames
            const canvas = document.createElement('canvas');
            canvas.width = 640;
            canvas.height = 480;
            const ctx = canvas.getContext('2d');

            if (!ctx) {
                throw new Error("Impossible d'obtenir un contexte 2D");
            }

            // Configurer le MediaRecorder
            const stream = canvas.captureStream(FPS);
            const mediaRecorder = new MediaRecorder(stream, {
                mimeType: 'video/webm;codecs=vp9',
                videoBitsPerSecond: 5000000 // 5 Mbps
            });

            mediaRecorderRef.current = mediaRecorder;
            chunksRef.current = [];

            mediaRecorder.ondataavailable = (e) => {
                if (e.data.size > 0) {
                    chunksRef.current.push(e.data);
                }
            };

            mediaRecorder.onstop = () => {
                const blob = new Blob(chunksRef.current, { type: 'video/webm' });
                const url = URL.createObjectURL(blob);
                setVideoURL(url);
                setIsGeneratingVideo(false);
            };

            mediaRecorder.start();

            // Dessiner chaque frame sur le canvas
            for (let i = 0; i < decodedFrames.length; i++) {
                const img = new Image();

                // Utiliser une promesse pour synchroniser le chargement des images
                await new Promise<void>((resolve, reject) => {
                    img.onload = () => {
                        ctx.clearRect(0, 0, canvas.width, canvas.height);
                        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

                        setVideoProgress(Math.round(((i + 1) / decodedFrames.length) * 100));
                        setTimeout(resolve, 1000 / FPS);
                    };

                    img.onerror = () => {
                        console.error(`Erreur lors du chargement de l'image ${i}`);
                        resolve();
                    };

                    img.src = decodedFrames[i];
                });
            }

            mediaRecorder.stop();

        } catch (err) {
            setError(`Erreur lors de la génération de la vidéo: ${err instanceof Error ? err.message : 'Erreur inconnue'}`);
            setIsGeneratingVideo(false);
        }
    };

    const downloadVideo = async (selectedStream: string) => {
        if (!videoURL) {
            setError("Aucune vidéo générée à télécharger");
            return;
        }

        try {
            const response = await fetch(videoURL);
            const webmBlob = await response.blob();

            const a = document.createElement('a');
            a.href = videoURL;
            a.download = `${selectedStream}_video.webm`;

            document.body.appendChild(a);
            a.click();

            setTimeout(() => {
                document.body.removeChild(a);
            }, 100);
        } catch (err) {
            setError(`Erreur lors du téléchargement: ${err instanceof Error ? err.message : 'Erreur inconnue'}`);
        }
    };

    return {
        isGeneratingVideo,
        videoProgress,
        videoURL,
        videoRef,
        generateVideo,
        downloadVideo,
        error,
        setError
    };
}
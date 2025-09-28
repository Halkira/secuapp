import {useState} from 'react';
import {CryptoOperation} from "../scripts/CryptoOperations";
import sessionManager from "../../components/sessionManager.tsx";
import PubKeyOperations, {GetProtectedPrivateKey} from "../scripts/KeyOperations.tsx";
import {useMyContext} from "../../components/MasterKeyContext.tsx";
import {arrayBufferToBase64, base64ToArrayBuffer} from "../../components/encoding.ts";

export function useVideoDecryption() {
    const [isLoading, setIsLoading] = useState<boolean>(false);
    const [progress, setProgress] = useState<number>(0);
    const [decodedFrames, setDecodedFrames] = useState<string[]>([]);
    const [decryptedData, setDecryptedData] = useState<{ timestamp: number, data: string }[]>([]);
    const [cryptedData, setCryptedData] = useState<any[]>([]);
    const [error, setError] = useState<string | null>(null);
    const { setMk } = useMyContext();


    const decryptFrames = async (frames: any[], streamId: string, encryptionKeybase64?: string) => {
        const decrypted: { timestamp: number, data: string }[] = [];

        setDecodedFrames([]);

        try {
            let decryptedStreamKeyBase64
            if (!encryptionKeybase64) {
                decryptedStreamKeyBase64 = await getKey(streamId);
            } else {
                const encryptedKeyBase64 = encryptionKeybase64;
                console.log("Test lvca : ", encryptedKeyBase64);

                const encryptedKeyBuffer = base64ToArrayBuffer(encryptedKeyBase64);

                const privateKey = await GetProtectedPrivateKey();

                try {
                    const decryptedStreamKeyBuffer = await window.crypto.subtle.decrypt(
                        {
                            name: "RSA-OAEP",
                        },
                        privateKey,
                        encryptedKeyBuffer
                    );

                    decryptedStreamKeyBase64 = arrayBufferToBase64(decryptedStreamKeyBuffer);

                } catch (specificError) {
                    console.error("Error decrypting shared key with RSA-OAEP:", specificError);
                    throw specificError;
                }
            }

            const decryptedStreamKeyBuffer = base64ToArrayBuffer(decryptedStreamKeyBase64);
            const decryptedStreamKeyU8 = new Uint8Array(decryptedStreamKeyBuffer);

            for (let i = 0; i < frames.length; i++) {
                try {
                    if (!frames[i].data || typeof frames[i].data !== 'string') {
                        console.error(`La frame ${i} n'a pas le format attendu:`, frames[i].data);
                        continue;
                    }

                    const base64Data = frames[i].data.includes('base64,')
                        ? frames[i].data.split('base64,')[1]
                        : frames[i].data;

                    const bytes = new Uint8Array(base64ToArrayBuffer(base64Data));

                    // Extraire l'IV (12 premiers octets) et les données chiffrées
                    const iv = bytes.slice(0, 12);
                    const encryptedData = bytes.slice(12);

                    let result;

                    // Dechiffrement
                    try {
                        result = await CryptoOperation(
                            encryptedData.buffer,
                            decryptedStreamKeyU8,
                            false,
                            iv
                        );
                    } catch (e) {
                        return console.error(e);
                    }

                    if (!result) {
                        return console.error(`Frame ${i}: Résultat de CryptoOperation undefined`);
                    }

                    let imageData: string;

                    if (typeof result.data === 'string') {
                        imageData = result.data;
                    } else {
                        const uint8Array = new Uint8Array(result.data);

                        let binaryStr = '';
                        for (let j = 0; j < uint8Array.byteLength; j++) {
                            binaryStr += String.fromCharCode(uint8Array[j]);
                        }

                        if (binaryStr.startsWith('data:image')) {
                            imageData = binaryStr;
                        } else {
                            const base64Str = btoa(binaryStr);
                            imageData = `data:image/jpeg;base64,${base64Str}`;
                        }
                    }

                    decrypted.push({
                        timestamp: frames[i].timestamp,
                        data: imageData
                    });

                    setDecodedFrames(prev => [...prev, imageData]);
                    setProgress(Math.round(((i + 1) / frames.length) * 100));
                } catch (err) {
                    const redFrame = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/wAALCAHgAoABAREA/8QAFQABAQAAAAAAAAAAAAAAAAAAAAn/xAAUEAEAAAAAAAAAAAAAAAAAAAAA/9oACAEBAAA/APVIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//Z";

                    decrypted.push({
                        timestamp: frames[i].timestamp,
                        data: redFrame
                    });

                    setDecodedFrames(prev => [...prev, redFrame]);
                }
            }

        } catch (err) {
            console.error(err);
            setError("Erreur lors du déchiffrement des frames.");
        }

        return decrypted;
    };

    const fetchAndDecryptVideo = async (streamId: string, encryptedKey?: string) => {
        if (!streamId) {
            setError("Veuillez sélectionner un stream");
            return;
        }

        setIsLoading(true);
        setError(null);
        setDecodedFrames([]);
        setProgress(0);

        try {
            const response = await fetch(`/api/dashcam/v0/videos/${streamId}`, {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
            });
            if (!response.ok) {
                throw new Error(`Erreur HTTP: ${response.status}`);
            }

            const videoData = await response.json();
            setCryptedData(videoData);

            if (!Array.isArray(videoData)) {
                throw new Error("Format de données invalide - tableau attendu");
            }

            console.log()

            const decryptedFramesData = await decryptFrames(videoData, streamId, encryptedKey);
            setDecryptedData(decryptedFramesData);
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'Erreur inconnue';
            setError(`Erreur lors du déchiffrement: ${errorMessage}`);
        } finally {
            setIsLoading(false);
        }
    };

    const exportDecryptedData = (selectedStream: string) => {
        if (!decryptedData.length) {
            setError("Aucune donnée déchiffrée à exporter");
            return;
        }

        try {
            const jsonData = JSON.stringify(decryptedData, null, 2);
            const blob = new Blob([jsonData], { type: 'application/json' });
            const url = URL.createObjectURL(blob);

            const a = document.createElement('a');
            a.href = url;
            a.download = `${selectedStream}_decrypted_data.json`;
            document.body.appendChild(a);
            a.click();

            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 100);
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'Erreur inconnue';
            setError(`Erreur lors de l'exportation: ${errorMessage}`);
        }
    };

    const exportCryptedData = (selectedStream: string) => {
        if (!cryptedData.length) {
            setError("Aucune donnée chiffrée à exporter");
            return;
        }

        try {
            const jsonData = JSON.stringify(cryptedData, null, 2);
            const blob = new Blob([jsonData], { type: 'application/json' });
            const url = URL.createObjectURL(blob);

            const a = document.createElement('a');
            a.href = url;
            a.download = `${selectedStream}_crypted_data.json`;
            document.body.appendChild(a);
            a.click();

            setTimeout(() => {
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }, 100);
        } catch (err) {
            const errorMessage = err instanceof Error ? err.message : 'Erreur inconnue';
            setError(`Erreur lors de l'exportation des données chiffrées: ${errorMessage}`);
        }
    };

    const getKey = async (streamId: string): Promise<string | null> => {
        // Récupere la master key, et déchiffre une clé d'un stream, donné en parametre
        try {
            // 1. Récupération de la masterKey
            const encMasterKey = await PubKeyOperations.GetMasterKey();
            if (!encMasterKey) {
                throw new Error("La clé maître chiffrée est invalide");
            }
            setMk(encMasterKey);

            // 2. Déverrouillage
            const masterKey = await PubKeyOperations.UnlockMasterKey(encMasterKey);
            if (!masterKey) {
                throw new Error("Impossible de déverrouiller la masterKey");
            }

            // 3. Récupération de la clé chiffrée
            const response = await fetch(`/api/dashcam/v0/dev/stream/key?stream_id=${streamId}`, {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
            });

            if (!response.ok) {
                throw new Error(`Erreur HTTP: ${response.status}`);
            }

            const encryptedStreamKeyAndIvBase64 = await response.json();
            if (!encryptedStreamKeyAndIvBase64.key) {
                throw new Error("Clé de stream absente dans la réponse");
            }

            const encryptedStreamKeyAndIvBuffer = base64ToArrayBuffer(encryptedStreamKeyAndIvBase64.key);

            if (encryptedStreamKeyAndIvBuffer.byteLength < 12) {
                throw new Error(`Format de clé invalide: taille insuffisante (${encryptedStreamKeyAndIvBuffer.byteLength} octets)`);
            }
            const iv = new Uint8Array(encryptedStreamKeyAndIvBuffer.slice(0, 12));
            const encryptedStreamKeyU8 = new Uint8Array(encryptedStreamKeyAndIvBuffer.slice(12));

            try {
                const decryptedStreamKeyBuffer = await window.crypto.subtle.decrypt(
                    {
                        name: "AES-GCM",
                        iv: iv.buffer
                    },
                    masterKey,
                    encryptedStreamKeyU8.buffer
                );

                return arrayBufferToBase64(decryptedStreamKeyBuffer);
            } catch (specificError) {
                console.error("Erreur spécifique au déchiffrement:", specificError);
                throw specificError;
            }
        } catch (formatError) {
            console.error("Erreur de format ou de décodage:", formatError);
            throw new Error("Erreur de format de la clé: " + formatError);
        }
    };

    return {
        isLoading,
        progress,
        decodedFrames,
        decryptedData,
        cryptedData,
        error,
        fetchAndDecryptVideo,
        exportDecryptedData,
        exportCryptedData,
        setError,
        getKey,
        decryptFrames
    };
}
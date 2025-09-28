import React, { useState, useRef, useEffect } from "react";
import { useVideoDecryption } from "../hooks/useVideoDecryption";
import { useVideoGeneration } from "../hooks/useVideoGeneration";
import sessionManager from "../../components/sessionManager.tsx";
import { arrayBufferToBase64, base64ToArrayBuffer } from "../../components/encoding.ts";

const videoCache = new Map<string, string>();

interface SharedVideoProps {
    title: string;
    date: string;
    size: string;
    shared: string[];
    onDelete?: () => void; // Ajout
    encryptKey?: string;
}

interface VideoProps {
    title: string;
    date: string;
    size: string;
    sharedTo: string | string[];
}

const SharedVideo: React.FC<SharedVideoProps> = ({ title, date, size, shared, onDelete, encryptKey }) => {
    const [showDownloadPopup, setShowDownloadPopup] = useState<boolean>(false);
    const [, setIsProcessing] = useState<boolean>(false);
    const [shouldDownload, setShouldDownload] = useState(false);
    const [cachedVideoURL, setCachedVideoURL] = useState<string | null>(null);


    const {
        isLoading: isDecrypting,
        progress: decryptProgress,
        decodedFrames,
        error: decryptError,
        fetchAndDecryptVideo
    } = useVideoDecryption();

    const {
        isGeneratingVideo,
        videoProgress,
        videoURL,
        generateVideo,
        downloadVideo,
        error: videoError
    } = useVideoGeneration();

    const closeDownloadPopup = () => {
        setShowDownloadPopup(false);
    };

    async function handleVideoDownload() {
        // Réinitialiser les refs
        isDownloading.current = false;
        isDownloadComplete.current = false;
        
        setShowDownloadPopup(true);
        setIsProcessing(true);
        setShouldDownload(true);
        
        try {
            console.log("Début du déchiffrement avec clé:", encryptKey);
            await fetchAndDecryptVideo(title, encryptKey);
        } catch (err) {
            console.error("Erreur lors du déchiffrement:", err);
            alert("Erreur lors du déchiffrement. Veuillez réessayer.");
            setIsProcessing(false);
            setShowDownloadPopup(false);
            setShouldDownload(false);
        }
    }

    const isDownloading = useRef(false);
    const isDownloadComplete = useRef(false);

    useEffect(() => {
        // Variable globale pour suivre l'état du téléchargement
        if (!shouldDownload || isDownloadComplete.current) return;
        
        const downloadSequence = async () => {
            // Garde pour éviter les exécutions multiples
            if (isDownloading.current) return;
            isDownloading.current = true;
            
            try {
                // 1. Attendre la fin du déchiffrement
                if (decodedFrames.length === 0 || isDecrypting) {
                    console.log("Attente du déchiffrement...");
                    isDownloading.current = false;
                    return;
                }
                
                // 2. Générer la vidéo si nécessaire
                if (!videoURL && !isGeneratingVideo) {
                    console.log(`Génération vidéo avec ${decodedFrames.length} frames`);
                    await generateVideo(decodedFrames);
                    isDownloading.current = false;
                    return;
                }
                
                // 3. Télécharger la vidéo une seule fois
                if ((videoURL || cachedVideoURL) && !isGeneratingVideo && !isDownloadComplete.current) {
                    console.log("Téléchargement de la vidéo...");
                    isDownloadComplete.current = true; // Marquer comme terminé AVANT l'appel
                    await downloadVideo(title);
                    
                    // Nettoyage
                    setIsProcessing(false);
                    setShowDownloadPopup(false);
                    setShouldDownload(false);
                }
            } catch (err) {
                console.error("Erreur dans la séquence de téléchargement:", err);
                setIsProcessing(false);
                setShowDownloadPopup(false);
                setShouldDownload(false);
            } finally {
                isDownloading.current = false;
            }
        };
        
        downloadSequence();
        
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [shouldDownload, decodedFrames, videoURL, cachedVideoURL, isGeneratingVideo, isDecrypting]);

    // Vérifier au chargement si la vidéo est en cache
    useEffect(() => {
        const cachedVideo = videoCache.get(title);
        if (cachedVideo) {
            setCachedVideoURL(cachedVideo);
        }
    }, [title]);

    // Mettre à jour le cache lorsque la vidéo est générée
    useEffect(() => {
        if (videoURL && !cachedVideoURL) {
            videoCache.set(title, videoURL);
            setCachedVideoURL(videoURL);
        }
    }, [videoURL, title, cachedVideoURL]);

    return (
        <section className="video">
            <h2>{title}</h2>
            <p>Date : {date}</p>
            <p>Size : {size}</p>
            <p>Shared by : {shared}</p>
            <button onClick={handleVideoDownload}>DOWNLOAD</button>
            {onDelete && (
                <button onClick={onDelete} className="delete-button">Delete</button>
            )}

            {/* Popup pour le téléchargement */}
            {showDownloadPopup && (
                <div className="video-popup-overlay">
                    <div className="video-popup-content">
                        <button className="close-button" onClick={closeDownloadPopup}>×</button>
                        <h3>Préparation du téléchargement</h3>

                        {isDecrypting && (
                            <div className="loading-container">
                                <p>Déchiffrement en cours...</p>
                                <div className="progress-bar">
                                    <div className="progress-fill" style={{ width: `${decryptProgress}%` }}></div>
                                </div>
                                <p>{decryptProgress}%</p>
                            </div>
                        )}

                        {!isDecrypting && isGeneratingVideo && (
                            <div className="loading-container">
                                <p>Reconstruction de la vidéo...</p>
                                <div className="progress-bar">
                                    <div className="progress-fill" style={{ width: `${videoProgress}%` }}></div>
                                </div>
                                <p>{videoProgress}%</p>
                            </div>
                        )}

                        {!isDecrypting && !isGeneratingVideo && videoURL && (
                            <div className="success-message">
                                <p>Téléchargement en cours...</p>
                            </div>
                        )}

                        {(decryptError || videoError) && (
                            <div className="error-message">
                                <p>Une erreur est survenue: {decryptError || videoError}</p>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </section>
    );
};

const Video: React.FC<VideoProps> = ({ title: videoId, date, size, sharedTo }) => {
    const [showPopup, setShowPopup] = useState<boolean>(false);
    const [showDownloadPopup, setShowDownloadPopup] = useState<boolean>(false);
    const [isProcessing, setIsProcessing] = useState<boolean>(false);
    const [cachedVideoURL, setCachedVideoURL] = useState<string | null>(null);
    const videoRefLocal = useRef<HTMLVideoElement>(null);
    const [shouldGenerate, setShouldGenerate] = useState<boolean>(false);
    const [shouldDownload, setShouldDownload] = useState(false);

    // états pour le partage
    const [showSharePopup, setShowSharePopup] = useState<boolean>(false);
    const [recipientEmail, setRecipientEmail] = useState<string>('');
    const [shareMessage, setShareMessage] = useState<string>('');

    // Utilisation des hooks personnalisés
    const {
        isLoading: isDecrypting,
        progress: decryptProgress,
        decodedFrames,
        error: decryptError,
        fetchAndDecryptVideo,
        getKey,
    } = useVideoDecryption();

    const {
        isGeneratingVideo,
        videoProgress,
        videoURL,
        generateVideo,
        downloadVideo,
        error: videoError
    } = useVideoGeneration();

    // Vérifier au chargement si la vidéo est en cache
    useEffect(() => {
        const cachedVideo = videoCache.get(videoId);
        if (cachedVideo) {
            setCachedVideoURL(cachedVideo);
        }
    }, [videoId]);

    // Mettre à jour le cache lorsque la vidéo est générée
    useEffect(() => {
        if (videoURL && !cachedVideoURL) {
            videoCache.set(videoId, videoURL);
            setCachedVideoURL(videoURL);
        }
    }, [videoURL, videoId, cachedVideoURL]);

    const handleDelete = async () => {
        const confirmDelete = window.confirm("Êtes-vous sûr de vouloir supprimer ce stream ?");

        if (confirmDelete) {
            try {
                const response = await fetch(`/api/dashcam/v0/videos/delete/${videoId}`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                    },
                });

                if (!response.ok) {
                    throw new Error(`Erreur HTTP: ${response.status}`);
                }

                if (videoCache.has(videoId)) {
                    videoCache.delete(videoId);
                }

                window.location.reload();
            } catch (err) {
                console.error(err);
                alert("La suppression a échoué. Veuillez réessayer.");
            }
        }
    };

    const handleWatch = async () => {
        setShowPopup(true);

        if (!videoId) {
            alert("L'ID du stream est requis pour visionner la vidéo.");
            setShowPopup(false);
            return;
        }

        if (cachedVideoURL) {
            return;
        }

        setIsProcessing(true);

        try {
            await fetchAndDecryptVideo(videoId);

            if (decryptError) {
                throw new Error(decryptError);
            }

            setShouldGenerate(true);

            // if (decodedFrames.length > 0) {
            //     await generateVideo(decodedFrames);
            //
            //     if (videoError) {
            //         throw new Error(videoError);
            //     }
            // }
        } catch (err) {
            console.error(err);
            alert("Impossible de charger la vidéo. Veuillez réessayer.");
            setShowPopup(false);
            setIsProcessing(false);
            setShouldGenerate(false);
        } finally {
            setIsProcessing(false);
        }
    };

    useEffect(() => {
        if (shouldGenerate && decodedFrames.length > 0) {
            (async () => {
                try {
                    await generateVideo(decodedFrames);
                    if (videoError) {
                        throw new Error(videoError);
                    }
                } catch (err) {
                    console.error(err);
                    alert("Impossible de générer la vidéo.");
                    setShowPopup(false);
                } finally {
                    setIsProcessing(false);
                    setShouldGenerate(false);
                }
            })();
        }
    }, [decodedFrames, shouldGenerate]);

    // Fonction de téléchargement simplifiée
    const handleDownload = async () => {
        // Si déjà en cache, télécharger directement
        if (cachedVideoURL || videoURL) {
            await downloadVideo(videoId);
            setShowDownloadPopup(false);
            return;
        }

        // Sinon, déclencher le process
        setShowDownloadPopup(true);
        setIsProcessing(true);
        setShouldDownload(true);
        await fetchAndDecryptVideo(videoId);
    };

    // Ce useEffect gère toute la séquence download
    useEffect(() => {
        if (!shouldDownload) return;

        // Attendre que les frames commencent à arriver
        if (decodedFrames.length === 0) {
            return;
        }
        
        // Attendre que le déchiffrement soit terminé
        if (isDecrypting) {
            console.log(`Déchiffrement en cours: ${decodedFrames.length} frames disponibles`);
            return;
        }
        
        // À ce stade, toutes les frames sont déchiffrées
        console.log(`Déchiffrement terminé: ${decodedFrames.length} frames disponibles`);

        // Générer la vidéo si ce n'est pas déjà fait
        if (!videoURL && !isGeneratingVideo) {
            console.log(`Génération vidéo avec ${decodedFrames.length} frames`);
            generateVideo(decodedFrames);
            return;
        }

        // Télécharger quand la vidéo est prête
        if ((videoURL || cachedVideoURL) && !isGeneratingVideo) {
            (async () => {
                try {
                    console.log("Téléchargement de la vidéo...");
                    await downloadVideo(videoId);
                } catch (err) {
                    console.error("Erreur lors du téléchargement:", err);
                    alert("Impossible de télécharger la vidéo.");
                } finally {
                    setIsProcessing(false);
                    setShowDownloadPopup(false);
                    setShouldDownload(false);
                }
            })();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [shouldDownload, decodedFrames, videoURL, cachedVideoURL, isGeneratingVideo, isDecrypting]);

    const closePopup = () => {
        setShowPopup(false);
    };

    const closeDownloadPopup = () => {
        setShowDownloadPopup(false);
    };

    // Récupérer clé publique du recipientEmail - adaptée pour le nouveau format
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
            // La réponse contient une liste de tuples [device_id, clé]
            console.log('Clés publiques récupérées:', data.pubkey_list);
            return data.pubkey_list || [];
        } catch (err) {
            console.error('Erreur lors de la récupération de la clé publique:', err);
            throw err;
        }
    };

    // Chiffrer la clé de chiffrement avec les clés publiques
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

    // Dans la fonction handleShareVideo
    const handleShareVideo = async () => {
        setShareMessage('Partage en cours...');
        try {
            // Récupérer la clé de stream
            const decryptedStreamKeyBase64 = await getKey(videoId);

            if (!decryptedStreamKeyBase64) {
                throw new Error("Impossible de récupérer la clé de chiffrement");
            }

            // Récupérer les clés publiques du destinataire (liste de tuples [clé, device_id])
            const publicKeysList = await fetchPublicKey(recipientEmail);

            console.log(publicKeysList)

            if (!publicKeysList || publicKeysList.length === 0) {
                throw new Error("Aucune clé publique trouvée pour cet utilisateur");
            }

            // Chiffrer la clé de stream avec toutes les clés publiques du destinataire
            const encryptedStreamKeysWithDevices = await encryptWithPublicKeys(decryptedStreamKeyBase64, publicKeysList);

            // Envoyer la demande de partage avec les clés chiffrées
            console.log(videoId, recipientEmail, encryptedStreamKeysWithDevices);
            const response = await fetch(`/api/dashcam/v0/share/video`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Access-Token': sessionManager.getAccessToken() || "",
                },
                body: JSON.stringify({
                    video_id: videoId,
                    recipient_email: recipientEmail,
                    shared_encryption_key: encryptedStreamKeysWithDevices
                }),
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || `Erreur HTTP: ${response.status}`);
            }

            setShareMessage('Vidéo partagée avec succès !');
            setRecipientEmail(''); // Effacer le champ email
            setTimeout(() => setShowSharePopup(false), 2000); // Fermer la popup après 2 secondes
        } catch (error) {
            if (error instanceof Error) {
                console.error(error);
                setShareMessage(`Échec du partage : ${error.message}`);
            }
        }
    };

    const handleCloseSharePopup = () => {
        setShowSharePopup(false);
        setRecipientEmail('');
        setShareMessage('');
    };


    return (
        <section className="video">
            <h2>{videoId}</h2>
            <p>Date : {date}</p>
            <p>Size : {size}</p>
            <p>Shared to : {sharedTo}</p>
            
            <button onClick={handleDownload}>DOWNLOAD</button>
            <section className="bottom-buttons">
                <button id="left" onClick={handleDelete}>DELETE</button>
                <button
                    id="middle"
                    onClick={handleWatch}
                    disabled={isProcessing}
                    className={isProcessing ? "loading-button" : ""}
                >
                    {isProcessing ? (
                        <span className="loading-spinner">
                            <span className="spinner-dot"></span>
                            <span className="spinner-dot"></span>
                            <span className="spinner-dot"></span>
                        </span>
                    ) : "WATCH"}
                </button>
                <button id="right" onClick={() => setShowSharePopup(true)}>SHARE</button>
            </section>
             {showSharePopup && (
                <div className="popup">
                    <div className="popup-content">
                        <h3>Partager la vidéo : {videoId}</h3>
                        <input
                            type="email"
                            placeholder="Entrez l'email du destinataire"
                            value={recipientEmail}
                            onChange={(e) => setRecipientEmail(e.target.value)}
                        />
                        <button onClick={handleShareVideo} disabled={!recipientEmail}>Partager</button>
                        <button onClick={handleCloseSharePopup}>Annuler</button>
                        {shareMessage && <p>{shareMessage}</p>}
                    </div>
                </div>
            )}

            {/* Popup pour visionner la vidéo */}
            {showPopup && (
                <div className="video-popup-overlay" onClick={closePopup}>
                    <div className="video-popup-content" onClick={e => e.stopPropagation()}>
                        <a className="close-button" onClick={closePopup}>×</a>
                        {isDecrypting && (
                            <div className="loading-container">
                                <p>Déchiffrement en cours...</p>
                                <div className="progress-bar">
                                    <div className="progress-fill" style={{ width: `${decryptProgress}%` }}></div>
                                </div>
                                <p>{decryptProgress}%</p>
                            </div>
                        )}

                        {!isDecrypting && isGeneratingVideo && (
                            <div className="loading-container">
                                <p>Reconstruction de la vidéo...</p>
                                <div className="progress-bar">
                                    <div className="progress-fill" style={{ width: `${videoProgress}%` }}></div>
                                </div>
                                <p>{videoProgress}%</p>
                            </div>
                        )}

                        {(decryptError || videoError) && (
                            <div className="error-message">
                                <p>Une erreur est survenue: {decryptError || videoError}</p>
                            </div>
                        )}

                        {/* Afficher la vidéo à partir du cache si disponible, sinon utiliser videoURL */}
                        {!isDecrypting && !isGeneratingVideo && (cachedVideoURL || videoURL) && (
                            <div className="video-container">
                                <video
                                    ref={videoRefLocal}
                                    src={cachedVideoURL || videoURL || ""}
                                    controls
                                    autoPlay
                                    className="video-player"
                                />
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Popup pour le téléchargement */}
            {showDownloadPopup && (
                <div className="video-popup-overlay">
                    <div className="video-popup-content">
                        <button className="close-button" onClick={closeDownloadPopup}>×</button>
                        <h3>Préparation du téléchargement</h3>

                        {isDecrypting && (
                            <div className="loading-container">
                                <p>Déchiffrement en cours...</p>
                                <div className="progress-bar">
                                    <div className="progress-fill" style={{ width: `${decryptProgress}%` }}></div>
                                </div>
                                <p>{decryptProgress}%</p>
                            </div>
                        )}

                        {!isDecrypting && isGeneratingVideo && (
                            <div className="loading-container">
                                <p>Reconstruction de la vidéo...</p>
                                <div className="progress-bar">
                                    <div className="progress-fill" style={{ width: `${videoProgress}%` }}></div>
                                </div>
                                <p>{videoProgress}%</p>
                            </div>
                        )}

                        {!isDecrypting && !isGeneratingVideo && (cachedVideoURL || videoURL) && (
                            <div className="success-message">
                                <p>Téléchargement en cours...</p>
                            </div>
                        )}

                        {(decryptError || videoError) && (
                            <div className="error-message">
                                <p>Une erreur est survenue: {decryptError || videoError}</p>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </section>
    );
};

export { SharedVideo, Video };
import { useState, useEffect } from "react";
import KeyOperations, {GetMasterKey} from "../scripts/KeyOperations.tsx";
import sessionManager from "../../components/sessionManager.tsx";
import { bufferToBase64URLString, base64URLStringToBuffer } from "@simplewebauthn/browser";

interface DeviceRequest {
    user_id: string;
    device_id: string;
    pubkey_device: string;
    request_timestamp: string;
    status: string;
}

export default function ApproveDevice() {
    const [deviceRequests, setDeviceRequests] = useState<DeviceRequest[]>([]);
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<string | null>(null);
    const [processingId, setProcessingId] = useState<string | null>(null);

    useEffect(() => {
        fetchDeviceRequests();
    }, []);

    const fetchDeviceRequests = async () => {
        setLoading(true);
        try {
            const response = await fetch("/api/dashcam/v0/device/requests", {
                method: "GET",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
            });

            if (!response.ok) {
                throw new Error("Échec de récupération des demandes d'appareils");
            }

            const data = await response.json();
            setDeviceRequests(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Une erreur est survenue");
        } finally {
            setLoading(false);
        }
    };

    const handleApprove = async (request: DeviceRequest) => {
        setProcessingId(request.device_id);
        try {
            const privateKey = await KeyOperations.GetProtectedPrivateKey();

            const masterKey = await GetMasterKey();

            const encryptedMasterKeyData = base64URLStringToBuffer(masterKey);
            const decryptedMasterKey = await window.crypto.subtle.decrypt(
                { name: "RSA-OAEP" },
                privateKey,
                encryptedMasterKeyData
            );

            const newDevicePkData = base64URLStringToBuffer(request.pubkey_device);
            const newDevicePubKey = await window.crypto.subtle.importKey(
                "spki",
                newDevicePkData,
                { name: "RSA-OAEP", hash: "SHA-256" },
                false,
                ["encrypt"]
            );

            const encryptedMasterKeyNewDevice = await window.crypto.subtle.encrypt(
                { name: "RSA-OAEP" },
                newDevicePubKey,
                decryptedMasterKey
            );

            const encryptedMasterKeyNewDeviceBase64 = bufferToBase64URLString(encryptedMasterKeyNewDevice);

            const response = await fetch("/api/dashcam/v0/device/approve", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
                body: JSON.stringify({
                    device_id: request.device_id,
                    pubkey: request.pubkey_device,
                    encrypted_master_key: encryptedMasterKeyNewDeviceBase64,
                }),
            });

            if (!response.ok) {
                throw new Error("Échec de l'approbation de l'appareil");
            }

            await fetchDeviceRequests();

        } catch (err) {
            setError(err instanceof Error ? err.message : "Erreur lors de l'approbation");
        } finally {
            setProcessingId(null);
        }
    };

    const handleReject = async (request: DeviceRequest) => {
        setProcessingId(request.device_id);
        try {
            const response = await fetch("/api/dashcam/v0/device/requests", {
                method: "DELETE",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
                },
                body: JSON.stringify({
                    temp_device_id: request.device_id,
                }),
            });

            if (!response.ok) {
                throw new Error("Échec du rejet de l'appareil");
            }

            // Actualiser la liste
            await fetchDeviceRequests();

        } catch (err) {
            setError(err instanceof Error ? err.message : "Erreur lors du rejet");
        } finally {
            setProcessingId(null);
        }
    };

    return (
        <div className="approval-container">
            <h1>Approuver de nouveaux appareils</h1>

            {error && <div className="error-message">{error}</div>}

            {loading ? (
                <div className="loading">Chargement des demandes...</div>
            ) : deviceRequests.length === 0 ? (
                <div className="no-requests">Aucune demande d'approbation en attente</div>
            ) : (
                <div className="request-list">
                    {deviceRequests.map((request) => (
                        <div key={request.device_id} className="request-item">
                            <div className="request-info">
                                <p className="user-id">Heure de la demande: {request.request_timestamp}</p>
                                <p className="device-id">ID temporaire: {request.device_id}</p>
                            </div>
                            <div className="request-actions">
                                <button
                                    onClick={() => handleApprove(request)}
                                    disabled={processingId === request.device_id}
                                    className="approve-button"
                                >
                                    {processingId === request.device_id ? "En cours..." : "Approuver"}
                                </button>
                                <button
                                    onClick={() => handleReject(request)}
                                    disabled={processingId === request.device_id}
                                    className="reject-button"
                                >
                                    {processingId === request.device_id ? "En cours..." : "Ignorer"}
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            <button onClick={fetchDeviceRequests} className="refresh-button">
                Rafraîchir la liste
            </button>
        </div>
    );
}
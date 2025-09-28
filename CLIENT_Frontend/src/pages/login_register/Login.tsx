import React, { useState, useEffect } from "react";
import Cookies from "js-cookie";
import sessionManager from "../../components/sessionManager.tsx";
import {useNavigate} from "react-router";
import KeyOperations from "../scripts/KeyOperations.tsx";
import {isStoreEmpty} from "../../components/StoreOperation.tsx";
import {base64URLStringToBuffer} from "@simplewebauthn/browser";

const LoginPage: React.FC = () => {
    const navigate = useNavigate();
    const [email, setEmail] = useState("");
    const [username, setUsername] = useState("");
    const [otp, setOtp] = useState("");
    const [error, setError] = useState<string | null>(null);
    const [isAuthenticating, setIsAuthenticating] = useState(false);
    const [step, setStep] = useState<1 | 2>(1);
    const [credential, setCredential] = useState<PublicKeyCredential>();
    const [waitingApproval, setWaitingApproval] = useState(false);
    const [fromNewDevice, setFromNewDevice] = useState(false);

    useEffect(() => {
    }, [credential]);

    const asArrayBuffer = (v: string) => Uint8Array.from(atob(v.replace(/_/g, '/').replace(/-/g, '+')), c => c.charCodeAt(0));

    async function authenticationOptions () {
        const response = await fetch("/api/dashcam/v0/authentication/options", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: email, username: username }),
        });

        const myCook = Cookies.get('csrf_session_token');
        sessionManager.setSessionToken(myCook || "");

        if (!response.ok) {
            throw new Error("Identifiants invalides.");
        }

        return response.json();
    }

    async function authenticationVerify(fromNewDevice: boolean) {
        const auth = "/api/dashcam/v0/authentication/verify"
        const newDevice = "/api/dashcam/v0/approved_device/verify"
        const response = await fetch(fromNewDevice ? newDevice : auth, {
            method: "POST",
            credentials : "include",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Session-Token": sessionManager.getSessionToken() || "",
            },
            body: JSON.stringify({ credential: credential, otp: otp }),
        });

        if (!response.ok) {
            throw new Error("Échec de l'authentification.");
        }

        const accessToken = Cookies.get("csrf_access_token")
        if (!accessToken) {
            throw new Error("Aucun jeton d'accès trouvé.");
        }
        sessionManager.setAccessToken(accessToken);

        const refreshToken = Cookies.get("csrf_refresh_token")
        if (!refreshToken) {
            throw new Error("Aucun jeton d'accès trouvé.");
        }
        sessionManager.setRefreshToken(refreshToken);

        sessionStorage.setItem("username", username);
        sessionStorage.setItem("email", email);
    }

    async function checkIfNewDevice() {
        try {
            return await isStoreEmpty();

        } catch {
           throw new Error("Erreur lors de la vérification de IndexedDB")
        }
    }

    async function handleNewDevice() {
        alert("Ceci est un nouvel appareil. Veuillez autoriser la connexion via l'un de vos appareils enregistrés.");

        const { stringPublicKey } = await KeyOperations.GenerateAndProtectKeyPair(email);
        const deviceId = localStorage.getItem("deviceId");

        await fetch("/api/dashcam/v0/device/add_request", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Session-Token": sessionManager.getSessionToken() || "",
            },
            body: JSON.stringify({
                pubkey_device: stringPublicKey,
                device_id: deviceId
            })
        });

        // Surveiller l'approbation de la demande
        setWaitingApproval(true);
        let approved = false;
        while (!approved) {
            const approvalResponse = await fetch(`/api/dashcam/v0/device/check_approval/${deviceId}`, {
                method: "GET",
                headers: {
                    "X-CSRF-Session-Token": sessionManager.getSessionToken() || "",
                },
            });

            if (approvalResponse.ok) {
                const approvalResult = await approvalResponse.json();
                if (approvalResult.is_approved) {
                    approved = true;
                    alert("Demande approuvée. Enregistrement de l'appareil en cours...");
                } else {
                    await new Promise((resolve) => setTimeout(resolve, 5000));
                }
            } else {
                throw new Error("Erreur lors de la vérification de l'approbation.");
            }
        }
        setWaitingApproval(false)

        // Démarrer l'enregistrement WebAuthn
        sessionManager.clearSessionToken();
        let approvedDeviceOptions;
        try {
            const response = await fetch("/api/dashcam/v0/approved_device/options", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({
                    email: email,
                    username: username,
                }),
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error("Erreur lors de la récupération des options de l'appareil approuvé." + errorText);
            }
            approvedDeviceOptions = await response.json()
        } catch (error) {
            console.error(error);
            throw new Error("Options error");
        }
        sessionManager.setSessionToken(Cookies.get("csrf_session_token") || '');

        approvedDeviceOptions.challenge = base64URLStringToBuffer(approvedDeviceOptions.challenge);
        approvedDeviceOptions.user.id = base64URLStringToBuffer(approvedDeviceOptions.user.id);

        const newCredential = await navigator.credentials.create({publicKey: approvedDeviceOptions}) as PublicKeyCredential;

        if (!newCredential) {
            throw new Error("Échec de l'enregistrement WebAuthn.");
        }
        alert("Nouvel appareil enregistré avec succès !");

        return newCredential;
    }

    const handleAuthentication = async () => {
        setError(null);
        setIsAuthenticating(true);

        try {
            if (step === 1) {
                const options = await authenticationOptions();

                const isNew = await checkIfNewDevice();

                if (isNew) {
                    setFromNewDevice(true)
                    const credential = await handleNewDevice()
                    setCredential(credential);
                } else {
                    options.challenge = asArrayBuffer(options.challenge);
                    options.allowCredentials = options.allowCredentials.map((cred: any) => ({
                        ...cred,
                        id: asArrayBuffer(cred.id),
                    }));

                    const credential = await navigator.credentials.get({publicKey: options}) as PublicKeyCredential;
                    setCredential(credential);
                }

                setStep(2);
            } else if (step === 2) {
                await authenticationVerify(fromNewDevice);

                alert("Authentification réussie !");

                navigate("/Home")
            }
        } catch (err) {
            if (err instanceof Error) setError(err.message);
        } finally {
            setIsAuthenticating(false);
        }
};

    return (
        <section className="main-container">
            <h1 className="title">Se connecter</h1>
            {step === 1 && (
                <>
                    <section className="input-section">
                        <label htmlFor="username">Nom d'utilisateur</label>
                        <input
                            id="username"
                            name="username"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                        />
                    </section>
                    <section className="input-section">
                        <label htmlFor="email">Email</label>
                        <input
                            id="email"
                            name="email"
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            required
                        />
                    </section>
                </>
            )}
            {step === 2 && (
                <section className="input-section">
                    <label htmlFor="otp">Code TOTP</label>
                    <input
                        id="otp"
                        name="otp"
                        value={otp}
                        onChange={(e) => {
                            const value = e.target.value;
                            if (/^\d*$/.test(value) && value.length <= 6) {
                                setOtp(value);
                            }
                        }}
                        required
                    />
                </section>
            )}
            {error && <div className="error-message">{error}</div>}
            <button onClick={handleAuthentication} disabled={isAuthenticating || (step === 2 && otp.length !== 6)}>
                {isAuthenticating ? "Authentification en cours..." : "Continuer"}
            </button>
            {waitingApproval && (
                <div className="loading-indicator">
                    Chargement en cours, veuillez patienter...
                </div>
            )}
        </section>
    );
};

export default LoginPage;
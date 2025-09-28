import React, { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import Cookies from 'js-cookie';
import KeyOperations from "../scripts/KeyOperations.tsx";
import TrustedForm from "../trusted/Trusted.tsx"
import {base64URLStringToBuffer} from "@simplewebauthn/browser";

interface RegisterFormState {
    username: string;
    email: string;
    firstname?: string;
    lastname?: string;
    organisation?: string;
    country?: string;
    totpCode: string;
    role?: string;
}

const RegisterPage: React.FC = () => {
    const [form, setForm] = useState<RegisterFormState>({
        username: "",
        email: "",
        totpCode: "",
        role: "regular",
    });

    const [options, setOptions] = useState<any>(null);
    const [qrUri, setQrUri] = useState<string>("");
    const [isRegistering, setIsRegistering] = useState(false);
    const [step, setStep] = useState<1 | 2 | 3 | 4>(1);

    const [regError, setRegError] = useState<string | null>(null);
    const [webauthnError, setWebauthnError] = useState<string | null>(null);
    const [myCookie, setMyCookie] = useState<string | null>(null);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
        const { name, value } = e.target;
        setForm(prev => ({ ...prev, [name]: value }));
    };

    const validateStepOne = (): boolean => {
        if (!form.username || form.username.length < 3) {
            setRegError("Le nom d'utilisateur doit contenir au moins 3 caractères.");
            return false;
        }
        if (!form.email || !/\S+@\S+\.\S+/.test(form.email)) {
            setRegError("Veuillez entrer une adresse email valide.");
            return false;
        }
        setRegError(null);
        return true;
    };

    const goToNextStep = async () => {
        if (step === 1) {
            if (!validateStepOne()) return;
            const options = await handleRegister();
            setOptions(options);
            if (options) setStep(2);
        } else if (step === 2) {
            const uri = await handleWebAuthnRegister(options);
            if (uri) {
                setQrUri(uri);
                setStep(3);
            }
        } else if (step === 3) {
            if (form.role === "trusted") {
                setStep(4);
            } else {
                alert("Inscription réussie ! Vous pouvez maintenant vous connecter.");
                window.location.href = "/Login";
            }
        }
    };

    const handleRegister = async (): Promise<any> => {
        try {
            const res = await fetch("/api/dashcam/v0/registration/options", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: form.email, username: form.username, role: form.role }),
            });

            const myCook = Cookies.get('csrf_session_token');
            setMyCookie(myCook || null)

            if (!res.ok) {
                const errorText = await res.text();
                console.error("Error fetching registration options:", errorText);

                if (res.status === 409) {
                    setRegError("Ce nom d'utilisateur n'est pas disponible.");
                } else if (res.status === 422) {
                    setRegError("Les champs d'email ou de nom d'utilisateur sont invalides.");
                } else {
                    setRegError("Une erreur est survenue. Veuillez réessayer.");
                }
                return null;
            }

            return await res.json();
        } catch (error) {
            console.error("Error fetching registration options:", error);
            setRegError("Une erreur est survenue. Veuillez réessayer.");
            return null;
        }
    };

    const handleWebAuthnRegister = async (options: any): Promise<string | null> => {
        setWebauthnError(null);
        setIsRegistering(true);

        try {
            // Etape Webauthn Front-Back
            options.user.id = base64URLStringToBuffer(options.user.id);  // De B64 vers Buffer
            options.challenge = base64URLStringToBuffer(options.challenge);

            const credential = await navigator.credentials.create({ publicKey: options }) as PublicKeyCredential;

            if (!credential) {
                console.error("No credential returned");
                return null;
            }

            // Etape 1
            const masterKey = await crypto.subtle.generateKey(
                { name: "AES-GCM", length: 256 },
                true,
                ["encrypt", "decrypt"]
            );
            const exportedMasterKey = await crypto.subtle.exportKey("jwk", masterKey);
            //


            const { publicKey, stringPublicKey } = await KeyOperations.GenerateAndProtectKeyPair(form.email);

            const encryptedMasterKey = await crypto.subtle.encrypt(
                { name: "RSA-OAEP" },
                await crypto.subtle.importKey(
                    "spki",
                    publicKey,
                    { name: "RSA-OAEP", hash: "SHA-256" },
                    false,
                    ["encrypt"]
                ),
                new TextEncoder().encode(JSON.stringify(exportedMasterKey))
            );

            const deviceId = localStorage.getItem("deviceId");

            const res = await fetch("/api/dashcam/v0/registration/verify", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Session-Token": myCookie || "",
                },
                body: JSON.stringify({
                    credential,
                    device_id: deviceId,
                    public_key: stringPublicKey,
                    master_key: btoa(String.fromCharCode(...new Uint8Array(encryptedMasterKey)))
                }),
            });

            if (!res.ok) {
                console.error("Registration failed:", res.statusText);
                return null;
            }

            const data = await res.json();
            return data.totp_provisioning_uri;
        } catch (error) {
            if (error instanceof Error) {
                if (error.name === 'NotAllowedError') {
                    setWebauthnError("La création de la clé d'accès a échoué. Veuillez réessayer et accepter la demande dans la fenêtre de dialogue.");
                } else {
                    setWebauthnError("Une erreur est survenue. Veuillez réessayer.");
                    console.error("Error during WebAuthn registration:", error);
                }
            }
            return null;
        } finally {
            setIsRegistering(false);
        }
    };

    return (
        <form onSubmit={(e) => { e.preventDefault(); goToNextStep(); }} className="main-container">
            <h1 className="title">S'enregister</h1>

            {step === 1 && (
                <>
                    <section className="input-section">
                        <label htmlFor="username">Nom d'utilisateur</label>
                        <input id="username" name="username" value={form.username} onChange={handleChange} required
                               minLength={3}/>
                    </section>

                    <section className="input-section">
                        <label htmlFor="email">Email</label>
                        <input id="email" name="email" type="email" value={form.email} onChange={handleChange}
                               required/>
                    </section>
                    <section className="input-section">
                        <label htmlFor="role">Rôle</label>
                        <select id="role" name="role" value={form.role || "regular"} onChange={handleChange}>
                            <option value="regular">Regular</option>
                            <option value="trusted">Trusted</option>
                        </select>
                    </section>

                    {regError && <div className="error-message">{regError}</div>}

                    <button type="submit">Continuer</button>
                </>
            )}

            {step === 2 && (
                <>
                    <h3>Il vous faut maintenant créer votre clé d'accès</h3>
                    <p><i>Une page de dialogue apparaîtra</i></p>
                    {webauthnError && <div className="error-message">{webauthnError}</div>}
                    <button type="button" onClick={goToNextStep} disabled={isRegistering}>
                        {isRegistering ? 'Création en cours...' : 'Créer ma clé d\'accès'}
                    </button>
                </>
            )}

            {step === 3 && qrUri && (
                <>
                    <article className="qr-section">
                        <p>Scannez ce QR code avec votre application Google Auth, Authy,... :</p>
                        <QRCodeSVG className="qrcode" value={qrUri} />
                    </article>
                    <button className="register" type="button" onClick={goToNextStep}>
                        J'ai scanné le QR code
                    </button>
                </>
            )}
            {step === 4 && (
              <div className="trusted-form-wrapper">
                <TrustedForm email={form.email} />
              </div>
            )}
        </form>
    );
};

export default RegisterPage;
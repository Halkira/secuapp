import React, {useEffect, useRef, useState} from "react";
import Cookies from "js-cookie";
import { NavLink, Outlet } from "react-router";
import sessionManager from "../../components/sessionManager";
import { MyContextProvider } from "../../components/MasterKeyContext.tsx";
import { QRCodeSVG } from "qrcode.react";

const REFRESH_INTERVAL_MS = 10 * 60 * 1000; // 10 minutes

const Root: React.FC = () => {
    const [ mk, setMk ] = useState<string | null>(null);
    const contextValue = {
        mk,
        setMk
    };
    const isAuthenticated = !!sessionManager.getAccessToken();
    const username = sessionStorage.getItem("username");
    const [qrUri, setQrUri] = useState<string>("");
    const [showQrPopup, setShowQrPopup] = useState<boolean>(false);
    const [showUsernamePopup, setShowUsernamePopup] = useState(false);
    const [newUsername, setNewUsername] = useState("");
    const [usernameError, setUsernameError] = useState<string | null>(null);

    const handleLogout = async () => {
        try {
            const accessToken = sessionManager.getAccessToken();
            const refreshToken = sessionManager.getRefreshToken();
            await fetch("/api/dashcam/v0/logout", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": accessToken || "",
                    "X-CSRF-Refresh-Token": refreshToken || "",
                },
            });

        } catch (error) {
            console.error("Erreur lors de la déconnexion:", error);

        } finally {
            sessionManager.clearAccessToken();
            sessionManager.clearRefreshToken();
            sessionStorage.removeItem("username");
            window.location.href = "/Login";
        }
    };


    const refreshAccessToken = async () => {
        try {

            const refreshToken = sessionManager.getRefreshToken();
            const response = await fetch("/api/dashcam/v0/refresh", {
                method: "POST",
                credentials: "include",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Refresh-Token": refreshToken || "",
                },
            });
            if (!response.ok) {
                throw new Error("Erreur lors du refresh du token");
            }
            const accessToken = Cookies.get("csrf_access_token")
            if (!accessToken) {
                throw new Error("Aucun jeton d'accès trouvé.");
            }
        sessionManager.setAccessToken(accessToken);
        } catch (err) {
            console.error("Erreur lors du refresh du token :", err);
        }
    };

    const refreshTimer = useRef<NodeJS.Timeout | null>(null);

    useEffect(() => {
        // Lance le timer seulement si l'utilisateur est connecté
        if (sessionManager.getAccessToken()) {
            refreshAccessToken(); // refresh immédiat au montage
            refreshTimer.current = setInterval(() => {
                refreshAccessToken();
            }, REFRESH_INTERVAL_MS);
        }
        return () => {
            if (refreshTimer.current) {
                clearInterval(refreshTimer.current);
            }
        };
    }, []);

    // Fonction pour régénérer le QR code et ouvrir la popup
    const handleRegenerateTOTP = async () => {
        try {
            const accessToken = sessionManager.getAccessToken();
            const response = await fetch("/api/dashcam/v0/totp/regenerate", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": accessToken || "",
                },
                credentials: "include",
            });
            if (!response.ok) throw new Error("Erreur lors de la régénération du QR code");
            const data = await response.json();
            setQrUri(data.totp_provisioning_uri);
            setShowQrPopup(true); // Ouvre la popup
        } catch (err) {
            alert("Erreur lors de la régénération du QR code");
        }
    };

    const handleChangeUsername = async (e: React.FormEvent) => {
        e.preventDefault();
        setUsernameError(null);
        try {
            const accessToken = sessionManager.getAccessToken();
            const response = await fetch("/api/dashcam/v0/user/username", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Access-Token": accessToken || "",
                },
                credentials: "include",
                body: JSON.stringify({ new_username: newUsername }),
            });
            if (!response.ok) {
                setUsernameError("Erreur lors du changement de username.");
                return;
            }
            sessionStorage.setItem("username", newUsername);
            setShowUsernamePopup(false);
            window.location.reload(); // Pour rafraîchir l'affichage du username
        } catch (err) {
            setUsernameError("Erreur lors du changement de username.");
        }
    };

    return (
        <MyContextProvider value={contextValue}>
            <section className="Root">
                <section className="Header">
                    <section className="left">
                        <h1>Application Security - Portal</h1>
                    </section>
                    <section className="right">
                        {!isAuthenticated ? (
                            <>
                                <NavLink className="navlink" to="/Login">Login</NavLink>
                                <NavLink className="navlink" to="/Register">Register</NavLink>
                            </>
                        ) : (
                            <>
                                <h3>{username}</h3>
                                <button className="navlink" onClick={handleLogout}>
                                    Logout
                                </button>
                                <button
                                    className="register"
                                    type="button"
                                    style={{ marginLeft: "1rem" }}
                                    onClick={handleRegenerateTOTP}
                                >
                                    Régénérer le TOTP
                                </button>
                                <button
                                    className="register"
                                    type="button"
                                    style={{ marginLeft: "1rem" }}
                                    onClick={() => setShowUsernamePopup(true)}
                                >
                                    Changer le username
                                </button>
                            </>
                        )}
                    </section>
                </section>
                <section className="content">
                    <section className="left">
                        <NavLink to="/Home" className="navlink" >
                            Home
                        </NavLink>
                        <NavLink to="/Stream" className="navlink" >
                            Stream
                        </NavLink>
                        <NavLink to="/Shared" className="navlink">
                            Shared
                        </NavLink>
                        <NavLink to="/ApproveDevice" className="navlink">
                            New Device
                        </NavLink>
                    </section>
                    <section className="right">
                        <Outlet />
                    </section>
                </section>
                <section className="Footer">
                    <article className="left">
                        <a href="https://www.unamur.be/fr">
                            <img id="icons" src="/images/unamur_blanc.png" alt="UNamur logo" />
                        </a>
                        <a href="https://www.henallux.be/">
                            <img id="icons" src="/images/henallux_logo.png" alt="Henallux logo" />
                        </a>
                    </article>
                    <article className="right">
                        <p>© 2025 Application Security - All rights reserved</p>
                    </article>
                </section>
                {showUsernamePopup && (
                    <div className="modal-overlay" style={{
                        position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
                        background: "rgba(0,0,0,0.6)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000
                    }}>
                        <div className="modal-content" style={{
                            background: "#2a2a2a", padding: 30, borderRadius: 10, textAlign: "center", color: "#f0f0f0"
                        }}>
                            <h2>Changer le username</h2>
                            <form onSubmit={handleChangeUsername}>
                                <input
                                    type="text"
                                    value={newUsername}
                                    onChange={e => setNewUsername(e.target.value)}
                                    placeholder="Nouveau username"
                                    required
                                    style={{ padding: "0.5rem", borderRadius: "5px", border: "1px solid #ccc" }}
                                />
                                <br /><br />
                                <button className="register" type="submit">
                                    Valider
                                </button>
                                <button
                                    className="register"
                                    type="button"
                                    style={{ marginLeft: "1rem" }}
                                    onClick={() => setShowUsernamePopup(false)}
                                >
                                    Annuler
                                </button>
                            </form>
                            {usernameError && <p style={{ color: "red" }}>{usernameError}</p>}
                        </div>
                    </div>
                )}
                {showQrPopup && (
                    <div className="modal-overlay" style={{
                        position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
                        background: "rgba(0,0,0,0.6)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000
                    }}>
                        <div className="modal-content" style={{
                            background: "#2a2a2a", padding: 30, borderRadius: 10, textAlign: "center", color: "#f0f0f0"
                        }}>
                            <h2>Scannez ce QR code avec votre application</h2>
                            {qrUri && <QRCodeSVG className="qrcode" value={qrUri} />}
                            <br />
                            <button className="register" type="button" onClick={() => setShowQrPopup(false)}>
                                Fermer
                            </button>
                        </div>
                    </div>
                )}
            </section>
        </MyContextProvider>
    );
}

export default Root;
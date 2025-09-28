import sessionManager from "../../components/sessionManager.tsx";
import { base64ToArrayBuffer }  from "../../components/encoding.ts";
import {base64URLStringToBuffer} from "@simplewebauthn/browser";


export const initDB = (): Promise<IDBDatabase> => {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open("SecuredKeysDB", 1);

        request.onerror = () => reject(new Error("Échec d'ouverture de la base de données"));

        request.onsuccess = () => resolve(request.result);

        request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains("privateKeys")) {
                db.createObjectStore("privateKeys", { keyPath: "id" });
            }
        };
    });
};

const GenerateAndProtectPrivateKey = async (userName: string) => {
    try {
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const userId = crypto.randomUUID();

        const credential = await navigator.credentials.create({
            publicKey: {
                rp: {
                    id: window.location.hostname,
                    name: "SecuApp"
                },
                user: {
                    id: new TextEncoder().encode(userId),
                    name: userName,
                    displayName: userName
                },
                challenge,
                pubKeyCredParams: [
                    { alg: -7, type: "public-key" },
                    { alg: -257, type: "public-key" }
                ],
                timeout: 60000,
                attestation: 'direct',
                authenticatorSelection: {
                    authenticatorAttachment: 'platform',
                    requireResidentKey: true,
                    userVerification: "required"
                }
            }
        });

        if (!credential) {
            throw new Error("Could not create encryptedKey");
        }

        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
        );

        const privateKeyData = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
        const privateKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(privateKeyData)));

        const webAuthnCredentialId = credential.id;

        const credentialIdBuffer = base64URLStringToBuffer(webAuthnCredentialId);
        const encryptionKeyHash = await window.crypto.subtle.digest('SHA-256', credentialIdBuffer);

        const aesKey = await window.crypto.subtle.importKey(
            'raw',
            encryptionKeyHash,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );

        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedPrivateKey = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            aesKey,
            new TextEncoder().encode(privateKeyBase64)
        );

        const encryptedKeyData = {
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encryptedPrivateKey)),
            webAuthnCredentialId: webAuthnCredentialId
        };

        const db = await initDB();
        await new Promise<void>((resolve, reject) => {
            const transaction = db.transaction(["privateKeys"], "readwrite");
            const store = transaction.objectStore("privateKeys");
            store.put({
                id: webAuthnCredentialId,
                encryptedKey: JSON.stringify(encryptedKeyData)
            });
            transaction.oncomplete = () => resolve();
            transaction.onerror = (event) => {
                console.error("Erreur de transaction IndexedDB:", (event.target as IDBRequest).error);
                reject((event.target as IDBRequest).error);
            };
        });

        const exportedPublicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
        const publicKeyString = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)));

        localStorage.setItem("deviceId", webAuthnCredentialId);
        localStorage.setItem("webAuthnId", webAuthnCredentialId);

        return { publicKey: exportedPublicKey, stringPublicKey: publicKeyString };
    } catch (err) {
        console.error("Erreur lors de la génération et de la protection de la clé privée:", err);
        throw err;
    }
};

export const GetProtectedPrivateKey = async (): Promise<CryptoKey> => {
    try {
        const webAuthnCredentialId = localStorage.getItem("deviceId");
        if (!webAuthnCredentialId) {
            throw new Error("Aucun credential WebAuthn trouvé dans la session (localStorage 'deviceId').");
        }

        const db = await initDB();
        const encryptedEntry = await new Promise<any>((resolve, reject) => {
            const transaction = db.transaction(["privateKeys"], "readonly");
            const store = transaction.objectStore("privateKeys");
            const request = store.get(webAuthnCredentialId);
            request.onsuccess = () => {
                if (request.result) {
                    resolve(request.result);
                } else {
                    reject(new Error(`Aucune entrée trouvée pour l'ID de credential WebAuthn: ${webAuthnCredentialId}`));
                }
            };
            request.onerror = (event) => reject(new Error(`Échec d'accès à IndexedDB: ${(event.target as IDBRequest).error}`));
        });

        const encryptedData = JSON.parse(encryptedEntry.encryptedKey);
        const iv = new Uint8Array(encryptedData.iv);
        const encryptedKey = new Uint8Array(encryptedData.data);

        const challengeForAssertion = crypto.getRandomValues(new Uint8Array(32));
        const decodedId = base64URLStringToBuffer(webAuthnCredentialId);

        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge: challengeForAssertion,
                allowCredentials: [{
                    id: decodedId,
                    type: 'public-key',
                }],
                userVerification: 'required'
            }
        });

        if (!assertion) {
            throw new Error("Authentification WebAuthn échouée : assertion nulle.");
        }

        const credentialIdBuffer = base64URLStringToBuffer(webAuthnCredentialId);
        const encryptionKeyBuffer = await window.crypto.subtle.digest('SHA-256', credentialIdBuffer);

        const aesKey = await window.crypto.subtle.importKey(
            'raw',
            encryptionKeyBuffer,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        const decryptedData = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            aesKey,
            encryptedKey
        );

        const privateKeyBase64 = new TextDecoder().decode(decryptedData);
        const privateKeyData = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0)).buffer;

        return await window.crypto.subtle.importKey(
            "pkcs8",
            privateKeyData,
            {
                name: "RSA-OAEP",
                hash: "SHA-256",
            },
            true,
            ["decrypt"]
        );
    } catch (err) {
        console.error("Erreur lors de la récupération de la clé privée:", err);
        throw err;
    }
};

const CheckPubKey = async (): Promise<boolean> => {
    try {
        const credentialId = sessionStorage.getItem("webAuthnCredentialId");
        if (!credentialId) {
            console.error("Aucun credential WebAuthn trouvé dans la session");
            return false;
        }

        const response = await fetch("/api/dashcam/v0/dev/user/device", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
            },
            body: JSON.stringify({
                webauthn_cred_id: credentialId
            }),
        });

        if (!response.ok) {
            throw new Error(`Erreur HTTP: ${response.status}`);
        }

        const result = await response.json();

        if (result.key !== false) {
            sessionStorage.setItem("publicKey", result.key);
            return true;
        } else {
            return false;
        }
    } catch (err) {
        console.error("Erreur lors de la vérification de la clé publique :", err);
        return false;
    }
};

export const GetMasterKey = async (): Promise<string> => {
    try {
        const deviceId = localStorage.getItem("deviceId");
        if (!deviceId) {
            throw new Error("No creds");
        }

        const response = await fetch("/api/dashcam/v0/dev/user/masterkey", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Access-Token": sessionManager.getAccessToken() || "",
            },
            body: JSON.stringify({
                device_id: deviceId
            }),
        });

        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const result = await response.json();

        if(result.masterkey) {
            return result.masterkey;
        } else {
            throw new Error("Master key not found");
        }
    } catch (err) {
        throw new Error("Error while getting MasterKey: " + err);
    }
}

const UnlockMasterKey = async (masterKeyEncrypted: string): Promise<CryptoKey | false> => {
    if (!masterKeyEncrypted) {
        return false;
    }
    try {
        const privateKey = await GetProtectedPrivateKey();
        const encryptedMasterKeyData: ArrayBuffer = base64ToArrayBuffer(masterKeyEncrypted);

        const decryptedMasterKeyData = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            encryptedMasterKeyData
        );

        const masterKeyObj = JSON.parse(new TextDecoder().decode(decryptedMasterKeyData));

        return await window.crypto.subtle.importKey(
            "jwk",
            masterKeyObj,
            {name: "AES-GCM"},
            false,
            ["encrypt", "decrypt"]
        );
    } catch (e){
        console.error(e);
        return false;
    }
}

export default { CheckPubKey, GenerateAndProtectKeyPair: GenerateAndProtectPrivateKey, GetMasterKey, GetProtectedPrivateKey, UnlockMasterKey };

/**
 * Fonction qui permet de chiffrer ou déchiffrer des données avec AES-GCM
 * @param {string | ArrayBuffer} data - Données à traiter (texte pour chiffrer, ArrayBuffer pour déchiffrer)
 * @param {Uint8Array} key - Clé de chiffrement/déchiffrement (32 octets pour AES-256)
 * @param {boolean} encrypt - true pour chiffrer, false pour déchiffrer
 * @param {Uint8Array} [iv] - Vecteur d'initialisation (requis pour déchiffrer)
 * @returns {Promise<{data: string | ArrayBuffer, iv?: Uint8Array}>} Résultat de l'opération
 */


export async function CryptoOperation(
    data: string | ArrayBuffer,
    key: Uint8Array,
    encrypt: boolean,
    iv?: Uint8Array
): Promise<{data: string | ArrayBuffer, iv?: Uint8Array}> {
    const cryptoKey = await window.crypto.subtle.importKey(
        "raw",
        key,
        { name: "AES-GCM" },
        true,
        ["encrypt", "decrypt"]
    );

    if (encrypt) {
        const ivToUse = generateRandomIV();
        const encodedData = new TextEncoder().encode(data as string);
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: ivToUse },
            cryptoKey,
            encodedData
        );

        return { data: encrypted, iv: ivToUse };
    } else {
        if (!iv) throw new Error('IV requis pour le déchiffrement');
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            cryptoKey,
            data as ArrayBuffer
        );

        const decryptedText = new TextDecoder().decode(decrypted);
        return { data: decryptedText };
    }
}

/**
 * Fonction pour déchiffrer une frame WebRTC
 * @param encryptedData - Données chiffrées (combinaison IV + données)
 * @param key - Clé de déchiffrement
 * @param cryptoKey
 * @returns Données déchiffrées ou null en cas d'erreur
 */
export async function decryptWebRTCFrame(encryptedData: ArrayBuffer, key: Uint8Array, cryptoKey: CryptoKey): Promise<ArrayBuffer | null> {
    if(!cryptoKey) {
        // Importer la clé pour le déchiffrement
        cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
    }

    try {
        const data = new Uint8Array(encryptedData);

        // Séparer l'IV et les données chiffrées
        const iv = data.slice(0, 12);
        const encryptedContent = data.slice(12);

        // Déchiffrer les données
        return await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            cryptoKey,
            encryptedContent
        );
    } catch (error) {
        console.error('Erreur lors du déchiffrement WebRTC:', error);
        return null;
    }
}

/**
 * Fonction pour générer une clé aléatoire
 * @returns {Promise<Uint8Array>} Clé AES-256 aléatoire
 */
export async function generateRandomKey(): Promise<Uint8Array> {
    return crypto.getRandomValues(new Uint8Array(32)); // Clé de 32 octets pour AES-256
}

/**
 * Fonction pour générer un IV aléatoire
 * @returns {Uint8Array} IV aléatoire
 */
export function generateRandomIV(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(12)); // IV de 12 octets pour AES-GCM
}
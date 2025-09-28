import {initDB} from "../pages/scripts/KeyOperations.tsx";

export async function isStoreEmpty(storeName: string = "privateKeys"): Promise<boolean> {
    const db = await initDB()

    return new Promise<boolean>((resolve, reject) => {
        const transaction = db.transaction([storeName], "readonly");
        const store = transaction.objectStore(storeName);
        const request = store.count();

        request.onsuccess = () => {
            resolve(request.result === 0);
        };

        request.onerror = () => {
            reject(new Error("Erreur lors de la vérification du store"));
        };
    });

}

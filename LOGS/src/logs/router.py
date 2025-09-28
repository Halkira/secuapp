import hashlib
import json

from fastapi import APIRouter, BackgroundTasks, HTTPException

from logs.constant import BASE64_PATTERN
from models import EncryptedLog
# Importer les modèles
from logs.models import FinalLogData, RawLogData

# Importer depuis utils
from logs.utils import (
    compute_etag,
    decrypt_log,
    get_utc_now,
    sign_log,
    verify_signature,
)

# Création du routeur
router = APIRouter(tags=["logs"])

@router.post("/logs")
async def receive_log(
    payload: EncryptedLog, background_tasks: BackgroundTasks,
):
    # Importer la connexion MongoDB depuis database.py
    from logs.database import collection

    try:
        # Déchiffrement du log
        log_dict = decrypt_log(
            payload.encrypted_key,
            payload.nonce,
            payload.encrypted_data,
            payload.tag,
        )
    except Exception as e:
        print(f"[ERROR] Erreur de déchiffrement: {e!s}")
        raise HTTPException(status_code=400, detail="Déchiffrement échoué")

    # IMPORTANT: Vérifier la signature
    try:
        verify_signature(log_dict, payload.signature)
    except Exception as e:
        print(f"[ERROR] Erreur de vérification de signature: {e!s}")
        raise HTTPException(status_code=400, detail="Signature invalide")

    # Vérification du hash courant AVANT transformation Pydantic
    if "current_hash" in log_dict:
        # Préparer une copie du log sans le champ current_hash pour recalculer le hash
        log_to_hash = dict(log_dict)
        stored_hash = log_to_hash.pop("current_hash")

        # Supprimer backend_signature du calcul du hash
        log_to_hash.pop("backend_signature", None)

        # Vérifier le hash
        json_str = json.dumps(log_to_hash, sort_keys=True)
        calculated_hash = hashlib.sha3_512(json_str.encode()).hexdigest()


        if calculated_hash != stored_hash:
            print(
                f"[ERROR] Hash invalide. Attendu: {stored_hash}, Calculé: {calculated_hash}",
            )
            raise HTTPException(status_code=400, detail="Hash de log invalide")
        print(f"[INFO] Hash vérifié avec succès")

    try:
        # Validation avec le modèle RawLogData seulement après vérification hash/signature
        raw_log = RawLogData(**log_dict)
        log = raw_log.model_dump()
    except Exception as e:
        print(f"[ERROR] Erreur de validation des données: {e!s}")
        raise HTTPException(
            status_code=400, detail=f"Données de log invalides: {e!s}",
        )

    # Ajoute la signature du backend dans le log final
    log["backend_signature"] = payload.signature

    # Vérification du previous_hash
    if "previous_hash" in log and log["previous_hash"] is not None:
        # Récupérer le dernier log de la base de données
        last_log = await collection.find_one(
            {},
            sort=[("received_at", -1)],
        )

        if last_log:
            # Extraction du hash précédent (format simplifié)
            last_hash = last_log.get("current_hash")

            if not last_hash:
                print("[ERROR] Hash non trouvé dans le log précédent")
                raise HTTPException(
                    status_code=500,
                    detail="Format de log précédent invalide",
                )

            if log["previous_hash"] != last_hash:
                print(
                    f"[ERROR] Previous hash invalide. Attendu: {last_hash}, Reçu: {log['previous_hash']}",
                )
                raise HTTPException(
                    status_code=400,
                    detail="Previous hash invalide",
                )
            print(
                f"[INFO] Previous hash vérifié avec succès",
            )
        elif log["previous_hash"] is not None:
            # Si c'est le premier log mais qu'un previous_hash est fourni
            print(
                f"[WARN] Premier log avec previous_hash non-null: {log['previous_hash']}",
            )

    # Préparation du document pour MongoDB
    log["received_at"] = get_utc_now().isoformat()

    etag = compute_etag(log)
    log["etag"] = etag

    # Signature du serveur
    server_signature = sign_log(log)
    log["log_server_signature"] = server_signature

    # Validation finale avec le modèle immuable
    try:
        final_log = FinalLogData(**log)
        # Convertir en dictionnaire pour insertion dans MongoDB
        log_to_store = dict(sorted(final_log.model_dump().items()))
    except Exception as e:
        print(f"[ERROR] Erreur de validation finale: {e!s}")
        raise HTTPException(
            status_code=500, detail="Erreur interne de validation",
        )

    # Insertion dans MongoDB
    await collection.insert_one(log_to_store)
    print(f"Log reçu et inséré avec succès")

    # Ajouter l'analyse du log en arrière-plan
    from logs.monitoring import analyze_log

    background_tasks.add_task(analyze_log, log_to_store)

    return {
        "status": "ok",
        "message": log.get("message", ""),
        "etag": etag,
        "server_signature": server_signature,
    }


@router.get("/health")
async def health_check():
    return {"status": "ok"}

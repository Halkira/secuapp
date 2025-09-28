import logging
from datetime import datetime, timedelta, timezone

from logs.database import alerts_collection, collection
from logs.models import Alert
from logs.utils import (
    safe_mongo_count,
    safe_mongo_find_one,
    validate_ip_address,
    validate_route,
)

# Configuration des seuils d'alerte
MAX_REQUESTS = 10  # Nombre maximum de requêtes autorisées
MONITORING_WINDOW = 10  # Fenêtre de surveillance en secondes

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
    ],
)
security_logger = logging.getLogger("security")

logger = logging.getLogger(__name__)


async def analyze_log(log: dict) -> None:
    """Analyse un log pour détecter une activité suspecte

    :param log: Dictionnaire contenant les données du log à analyser
                (déjà validé avec FinalLogData)
    """
    # Extraction des informations pertinentes
    ip_address = log.get("ip_address")
    route = log.get("route")
    timestamp = log.get("received_at") or log.get("created_at")

    if not (ip_address and route and timestamp):
        msg = (
            f"Log incomplet pour l'analyse - "
            f"manque ip_address, route ou timestamp: {log}"
        )
        logger.warning(msg)
        return

    # Validation supplémentaire des types (défense en profondeur)
    # Note: cette étape est redondante car le log a déjà été validé,
    # mais c'est une bonne pratique de sécurité en profondeur
    if not validate_ip_address(ip_address):
        logger.error(f"Format d'adresse IP invalide: {ip_address}")
        return

    if not validate_route(route):
        logger.error(f"Format de route invalide: {route}")
        logger.debug(
            f"Route non valide (caractères): {[ord(c) for c in route]}",
        )
        return

    # Conversion de la date au format datetime si elle est en string
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00"),
            )
        except ValueError:
            logger.error(f"Format de timestamp invalide: {timestamp}")
            return

    # Définir la fenêtre de temps pour la recherche
    window_start = timestamp - timedelta(seconds=MONITORING_WINDOW)

    try:
        # Interroger MongoDB pour compter les logs récents de cette IP sur cette route
        # en utilisant la fonction sécurisée
        query = {
            "ip_address": ip_address,
            "route": route,
            "received_at": {
                "$gte": window_start.isoformat(),
                "$lte": timestamp.isoformat(),
            },
        }

        logs_count = await safe_mongo_count(collection, query)

        # Vérifier s'il y a déjà une alerte récente
        alert_query = {
            "ip_address": ip_address,
            "route": route,
            "timestamp": {
                "$gte": (timestamp - timedelta(minutes=5)).isoformat(),
            },
        }

        existing_alert = await safe_mongo_find_one(
            alerts_collection, alert_query,
        )

        # Calculer le seuil dynamique
        current_threshold = MAX_REQUESTS
        if existing_alert:
            # Augmenter le seuil de 50% si une alerte a déjà été générée
            # Cela permet de ne générer de nouvelles alertes que si l'activité s'intensifie
            current_threshold = int(MAX_REQUESTS * 2)

        # Vérifier si le seuil (potentiellement augmenté) est dépassé
        if logs_count > current_threshold:
            # Générer l'alerte en utilisant le modèle Pydantic immuable
            alert_data = {
                "timestamp": timestamp.isoformat(),
                "ip_address": ip_address,
                "route": route,
                "logs_count": logs_count,
                "window_seconds": MONITORING_WINDOW,
                "threshold": current_threshold,
                "base_threshold": MAX_REQUESTS,
                "is_escalation": existing_alert is not None,
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }

            # Valider avec Pydantic avant insertion (crée un objet immuable)
            alert = Alert(**alert_data)

            # Insérer l'alerte validée
            await alerts_collection.insert_one(
                alert.model_dump(),
            )  # Utiliser model_dump() au lieu de dict()

            # Message d'alerte approprié
            if existing_alert:
                alert_message = (
                    f"ESCALADE D'ALERTE: Activité "
                    f"suspecte intensifiée - IP: {ip_address}, "
                    f"{logs_count} requêtes "
                    f"(seuil: {current_threshold}) sur {route}"
                )
                security_logger.error(alert_message)
            else:
                alert_message = (
                    f"ALERTE DE SÉCURITÉ: Activité "
                    f"suspecte détectée - IP: {ip_address}, "
                    f"{logs_count} requêtes en "
                    f"{MONITORING_WINDOW} secondes sur {route}"
                )
                security_logger.warning(alert_message)
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse du log: {e}")


async def get_monitoring_stats():
    """Récupère les statistiques actuelles de monitoring"""
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=MONITORING_WINDOW)

    try:
        # Agréger les statistiques par IP et route
        pipeline = [
            {"$match": {"received_at": {"$gte": window_start.isoformat()}}},
            {
                "$group": {
                    "_id": {"ip": "$ip_address", "route": "$route"},
                    "count": {"$sum": 1},
                    "last_access": {"$max": "$received_at"},
                },
            },
            {
                "$project": {
                    "ip_address": "$_id.ip",
                    "route": "$_id.route",
                    "count": 1,
                    "last_access": 1,
                    "_id": 0,
                },
            },
        ]

        results = await collection.aggregate(pipeline).to_list(None)

        # Validation supplémentaire des résultats
        ip_stats = {}
        for result in results:
            ip = result.get("ip_address")
            route = result.get("route")

            # Valider l'IP et la route
            if not (
                ip
                and validate_ip_address(ip)
                and route
                and validate_route(route)
            ):
                logger.warning(
                    f"Résultat d'agrégation invalide ignoré: {result}",
                )
                continue

            if ip not in ip_stats:
                ip_stats[ip] = []

            ip_stats[ip].append(
                {
                    "route": route,
                    "count": result.get("count", 0),
                    "last_access": result.get("last_access", ""),
                },
            )

        return {
            "monitoring_window_seconds": MONITORING_WINDOW,
            "max_requests_threshold": MAX_REQUESTS,
            "current_time": now.isoformat(),
            "ip_stats": ip_stats,
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques: {e}")
        return {
            "error": "Erreur lors de la récupération des statistiques",
            "current_time": now.isoformat(),
        }


async def get_alerts(hours: int = 24):
    """Récupère les alertes générées durant les dernières heures"""
    try:
        # Validation de la plage horaire
        if (
            not isinstance(hours, int) or hours <= 0 or hours > 168
        ):  # Max 7 jours
            hours = 24  # Valeur par défaut sécurisée

        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Requête sécurisée avec safe_mongo_find
        from logs.utils import safe_mongo_find

        query = {"timestamp": {"$gte": start_time.isoformat()}}
        cursor = await safe_mongo_find(
            alerts_collection,
            query,
            projection={"_id": 0},  # Exclure l'ID MongoDB
        )

        alerts = await cursor.sort("timestamp", -1).to_list(None)

        # Validation supplémentaire des alertes
        validated_alerts = []
        for alert_dict in alerts:
            try:
                # Valider avec Pydantic (crée un objet immuable)
                alert = Alert(**alert_dict)
                validated_alerts.append(
                    alert.model_dump(),
                )  # Utiliser model_dump() au lieu de dict()
            except Exception as e:
                logger.warning(f"Alerte invalide ignorée: {e}")

        return {
            "hours": hours,
            "alert_count": len(validated_alerts),
            "alerts": validated_alerts,
        }
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des alertes: {e}")
        return {
            "hours": hours,
            "error": "Erreur lors de la récupération des alertes",
            "alert_count": 0,
            "alerts": [],
        }

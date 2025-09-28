import re
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal
import constant
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from logs.constant import (
    BASE64_PATTERN,
    IPV4_PATTERN,
    IPV6_PATTERN,
    IPV6_COMPRESSED_PATTERN,
    ALLOWED_CHARS,
)


class EncryptedLog(BaseModel):
    encrypted_key: str
    nonce: str  # Changé de "iv" à "nonce"
    encrypted_data: str
    tag: str  # Ajouté pour GCM
    signature: str
    created_at: str | None = None


LogLevelType = Literal["INFO", "WARNING", "ERROR", "CRITICAL", "DEBUG"]


# Fonction de validation pour IPAddress (plus stricte pour IPv4)
def validate_ip_address(v: str) -> str:
    """Valide le format d'une adresse IP (IPv4 ou IPv6)"""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Validation plus stricte pour IPv4 (chaque octet entre 0 et 255)
    ipv4_match = IPV4_PATTERN.match(v)

    if ipv4_match:
        # Vérifier que chaque octet est entre 0 et 255
        for octet in ipv4_match.groups():
            if not (0 <= int(octet) <= 255):
                raise ValueError(f"IPv4 octet hors limite: {octet}")
        return v

    # Valider IPv6 (plus stricte)
    if IPV6_PATTERN.match(v):
        return v

    # Format IPv6 compressé
    if IPV6_COMPRESSED_PATTERN.match(v):
        return v

    raise ValueError("Format d'adresse IP invalide")


# Définir un type IPAddress avec validation
IPAddress = Annotated[str, BeforeValidator(validate_ip_address)]


# Fonction de validation pour RouteStr
def validate_route(v: str) -> str:
    """Valide le format d'une route d'API"""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Valider le format de route (doit commencer par /)
    if not v.startswith("/"):
        raise ValueError("La route doit commencer par /")
    return v


# Définir un type RouteStr avec validation
RouteStr = Annotated[str, BeforeValidator(validate_route)]


def validate_token_partial(v: str) -> str:
    """Valide le format d'un token partiel"""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Pour token_partial, on accepte un format plus souple (premiers caractères + ...)
    if not re.match(r"^[a-zA-Z0-9_\-\.]{1,10}(\.{3})?$", v):
        raise ValueError("Format de token partiel invalide")

    return v
TokenPartialStr = Annotated[str, BeforeValidator(validate_token_partial)]

# Fonction de validation pour HashStr
def validate_hash(v: str) -> str:
    """Valide le format d'un hash SHA3-512"""
    if not isinstance(v, str):
        raise TypeError("string required")

    # SHA3-512 hashes are 128 characters in hex
    if not re.match(r"^[0-9a-f]{128}$", v):
        raise ValueError("Format de hash SHA3-512 invalide")

    return v


# Définir un type HashStr avec validation
HashStr = Annotated[str, BeforeValidator(validate_hash)]


# Fonction de validation pour les signatures backend (exactement 344 caractères)
def validate_backend_signature(v: str) -> str:
    """Valide le format d'une signature backend PSS avec SHA3-512 et RSA-2048"""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Vérifier que c'est une chaîne base64 valide
    if not BASE64_PATTERN.match(v):
        raise ValueError("Format de signature base64 invalide")

    # Pour RSA-2048 avec PSS et SHA3-512, longueur EXACTE attendue
    if len(v) != 344:
        raise ValueError(
            f"Longueur de signature backend invalide: {len(v)}, attendu exactement 344 caractères",
        )

    return v


# Définir un type BackendSignatureStr avec validation précise
BackendSignatureStr = Annotated[
    str, BeforeValidator(validate_backend_signature),
]


# Fonction de validation pour SignatureStr générique (pour rétrocompatibilité)
def validate_signature(v: str) -> str:
    """Valide le format d'une signature base64"""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Les signatures PSS base64 ont généralement une longueur fixe
    # Vérifier le format base64
    if not BASE64_PATTERN.match(v):
        raise ValueError("Format de signature base64 invalide")

    # Vérifier la longueur (dépend de l'algorithme exact)
    if len(v) != 344:
        raise ValueError(f"Longueur de signature invalide: {len(v)}")

    return v


# Définir un type SignatureStr avec validation
SignatureStr = Annotated[str, BeforeValidator(validate_signature)]


# Fonction de validation pour Timestamp ISO 8601
def validate_iso8601(v: str) -> str:
    """Valide le format d'un timestamp ISO 8601"""
    if not isinstance(v, str):
        raise TypeError("string required")

    try:
        # Valider le format ISO 8601
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))

        # Vérifier que la date est raisonnable (pas dans un futur lointain)
        max_future = datetime.now(dt.tzinfo).replace(
            year=datetime.now().year + 1,
        )
        if dt > max_future:
            raise ValueError(f"Timestamp trop dans le futur: {v}")

        # Vérifier que la date n'est pas trop dans le passé
        min_past = datetime(2020, 1, 1, tzinfo=dt.tzinfo)
        if dt < min_past:
            raise ValueError(f"Timestamp trop ancien: {v}")

        return v
    except ValueError as e:
        if "fromisoformat" in str(e):
            raise ValueError(
                "Format de timestamp invalide, doit être ISO 8601",
            )
        raise


# Définir un type TimestampStr avec validation
TimestampStr = Annotated[str, BeforeValidator(validate_iso8601)]


# Fonction de validation pour UserID
def validate_user_id(v: str) -> str:
    """Valide le format d'un identifiant utilisateur"""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Format attendu pour un ID utilisateur
    if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", v):
        raise ValueError("Format d'identifiant utilisateur invalide")

    return v


# Définir un type UserIDStr avec validation
UserIDStr = Annotated[str, BeforeValidator(validate_user_id)]


# Fonction de validation pour SessionID
def validate_session_id(v: str) -> str:
    """Valide le format d'un identifiant de session"""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Format attendu pour un ID de session (généralement alphanumérique avec une longueur fixe)
    if not re.match(r"^[a-zA-Z0-9_-]{8,64}$", v):
        raise ValueError("Format d'identifiant de session invalide")

    return v


# Définir un type SessionIDStr avec validation
SessionIDStr = Annotated[str, BeforeValidator(validate_session_id)]


# Fonction de validation pour UserAgent
def validate_user_agent(v: str) -> str:
    """Valide le format d'un User-Agent"""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Longueur maximale pour éviter les attaques par déni de service
    if len(v) > 512:
        raise ValueError("User-Agent trop long (max 512 caractères)")


    # Caractères autorisés dans un User-Agent
    if not all(32 <= ord(c) <= 126 for c in v):
        raise ValueError("User-Agent contient des caractères non imprimables")

    return v


# Définir un type UserAgentStr avec validation
UserAgentStr = Annotated[str, BeforeValidator(validate_user_agent)]


# Fonction de validation pour les tags
def validate_tag(v: str) -> str:
    """Valide le format d'un tag"""
    if not isinstance(v, str):
        raise TypeError("string required")

    # Format attendu pour un tag
    if not re.match(r"^[a-zA-Z0-9_-]{1,32}$", v):
        raise ValueError("Format de tag invalide")

    return v


# Définir un type TagStr avec validation
TagStr = Annotated[str, BeforeValidator(validate_tag)]


# Modèle pour la validation des métadonnées
class LogMetadata(BaseModel):
    """Modèle pour valider les métadonnées des logs"""

    # Types autorisés pour les valeurs de métadonnées
    model_config = ConfigDict(extra="forbid")

    # Définir ici les champs autorisés pour les métadonnées
    application: str | None = None
    version: str | None = None
    environment: Literal["development", "testing", "production"] | None = None

    # Validateur pour les valeurs de type chaîne
    @field_validator("application", "version")
    @classmethod
    def validate_string_values(cls, v):
        if v is not None and len(v) > 64:
            raise ValueError(
                "Valeur de métadonnée trop longue (max 64 caractères)",
            )
        return v


class RawLogData(BaseModel):
    """Modèle pour valider initialement les logs déchiffrés (mutable pour permettre les modifications)"""

    # Champs obligatoires
    message: Annotated[str, StringConstraints(min_length=1, max_length=1024)]
    level: LogLevelType | None = None

    # Utiliser le type précis pour la signature backend avec exactement 344 caractères
    backend_signature: BackendSignatureStr

    # Champs qui étaient obligatoires mais sont maintenant optionnels
    ip_address: IPAddress | None = None
    route: RouteStr | None = None
    severity: LogLevelType | None = None

    # Champs spécifiques au hash et à la signature
    created_at: TimestampStr | None = None
    previous_hash: HashStr | None = None
    current_hash: HashStr | None = None

    # Champs optionnels
    user_id: UserIDStr | None = None
    session_id: SessionIDStr | None = None
    user_agent: UserAgentStr | None = None
    token_partial: TokenPartialStr | None = None

    # Champs supplémentaires
    metadata: LogMetadata | None = None
    tags: list[TagStr] | None = None

    # Validation croisée des champs
    @model_validator(mode="after")
    def validate_log_consistency(self):
        """Valide la cohérence entre les différents champs du log"""
        # Si level est défini, severity doit être égal à level ou None
        if (
            self.level is not None
            and self.severity is not None
            and self.level != self.severity.value
        ):
            raise ValueError(
                "Les champs level et severity doivent être identiques s'ils sont tous deux définis",
            )

        # Si previous_hash est défini, current_hash doit aussi être défini
        if self.previous_hash is not None and self.current_hash is None:
            raise ValueError(
                "current_hash doit être défini si previous_hash est défini",
            )

        # Si session_id est défini, user_id devrait normalement être défini aussi
        if self.session_id is not None and self.user_id is None:
            raise ValueError(
                "user_id devrait être défini si session_id est défini",
            )

        return self


class FinalLogData(RawLogData):
    """Modèle pour stocker les logs validés et complets (immuable)"""

    # Configuration pour rendre le modèle immuable
    model_config = ConfigDict(frozen=True)

    # Champs ajoutés par le serveur
    received_at: TimestampStr
    etag: HashStr
    # Utiliser le même type précis pour la signature du serveur
    log_server_signature: BackendSignatureStr


class Alert(BaseModel):
    # Configuration pour rendre le modèle immuable
    model_config = ConfigDict(frozen=True, extra="forbid")

    timestamp: TimestampStr
    ip_address: IPAddress
    route: RouteStr
    logs_count: int = Field(gt=0, lt=10000)  # Limite supérieure raisonnable
    window_seconds: int = Field(gt=0, lt=3600)  # Max 1 heure
    threshold: int = Field(gt=0, lt=1000)  # Limite supérieure raisonnable
    base_threshold: int = Field(gt=0, lt=1000)  # Limite supérieure raisonnable
    is_escalation: bool
    detected_at: TimestampStr

    # Validation croisée
    @model_validator(mode="after")
    def validate_alert_consistency(self):
        """Valide la cohérence entre les différents champs de l'alerte"""
        # Le seuil devrait être au moins égal au seuil de base
        if self.threshold < self.base_threshold:
            raise ValueError(
                "Le seuil ne peut pas être inférieur au seuil de base",
            )

        # Si c'est une escalade, le seuil devrait être supérieur au seuil de base
        if self.is_escalation and self.threshold <= self.base_threshold:
            raise ValueError(
                "Une escalade devrait avoir un seuil supérieur au seuil de base",
            )

        # La date de détection ne peut pas être antérieure au timestamp
        detected = datetime.fromisoformat(
            self.detected_at.replace("Z", "+00:00"),
        )
        event = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
        if detected < event:
            raise ValueError(
                "La date de détection ne peut pas être antérieure à l'événement",
            )

        return self


class MongoQueryOperator(str, Enum):
    """Énumération des opérateurs MongoDB autorisés"""

    GTE = "$gte"
    LTE = "$lte"
    EQ = "$eq"
    IN = "$in"
    GT = "$gt"
    LT = "$lt"


class MongoQuery:
    """Classe utilitaire pour construire des requêtes MongoDB sécurisées"""

    # Opérateurs MongoDB autorisés
    ALLOWED_OPERATORS = {op.value for op in MongoQueryOperator}

    @staticmethod
    def is_safe_query(query: dict) -> bool:
        """Vérifie si une requête MongoDB est sûre"""
        if not isinstance(query, dict):
            return False

        for key, value in query.items():
            # Vérifier si la clé est un opérateur
            if isinstance(key, str) and key.startswith("$"):
                if key not in MongoQuery.ALLOWED_OPERATORS:
                    return False

                # Vérifier les types de valeurs pour chaque opérateur
                if (key == "$in" and not isinstance(value, list)) or (
                    key != "$in"
                    and not isinstance(value, (str, int, float, bool))
                ):
                    return False

            # Vérifier récursivement les sous-dictionnaires
            elif isinstance(value, dict):
                if not MongoQuery.is_safe_query(value):
                    return False
            # Vérifier les types de valeurs autorisés
            elif not isinstance(value, (str, int, float, bool, list)):
                return False

            # Vérifier le contenu des listes
            if isinstance(value, list) and not all(
                isinstance(item, (str, int, float, bool)) for item in value
            ):
                return False

        return True

    @staticmethod
    def build_query(query_dict: dict) -> dict:
        """Construit une requête MongoDB sécurisée"""
        # Vérifier si la requête est sûre
        if not MongoQuery.is_safe_query(query_dict):
            raise ValueError("Requête MongoDB non sécurisée")

        return query_dict

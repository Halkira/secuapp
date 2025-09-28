import base64
import logging
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Annotated

from async_fastapi_jwt_auth import AuthJWT
from cryptography.exceptions import InvalidTag
from fastapi import (
    APIRouter,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.params import Depends
from fastapi.responses import JSONResponse
from pydantic import EmailStr, SecretStr, ValidationError
from redis import Redis
from sqlmodel import Session as DBSession
from sqlmodel import select
from starsessions import load_session, session
from webauthn import options_to_json
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidJSONStructure,
    InvalidRegistrationResponse,
)

from backend import database, lib, log_service, models, redis, schemas, utils
from backend.database import (
    Device,
    EncMasterKey,
    MasterKey,
    StreamKey,
    get_db_engine,
)
from backend.lib import (
    authentication,
    authentication_all,
    authentication_regular,
    authentication_trusted,
    authentication_websocket_regular,
)
from backend.redis import get_redis

from .database.user import User

if TYPE_CHECKING:
    from pathlib import Path

    from starsessions.session import SessionHandler
    from webauthn.authentication.verify_authentication_response import (
        VerifiedAuthentication,
    )
    from webauthn.helpers.structs import (
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRequestOptions,
    )
    from webauthn.registration.verify_registration_response import (
        VerifiedRegistration,
    )

import contextlib

from fastapi import WebSocket
from fastapi.responses import FileResponse

from backend.database.shared_stream import (
    SharedStream,  # Importe les modèles SharedStream
)
from backend.database.shared_video import (
    SharedVideo,  # Importe les modèles SharedVideo
)
from backend.database.stream import Stream

from .helper.common import list_active_streams_data
from .helper.video_service import (
    delete_video_file,
    get_video_file,
    list_videos_data,
)
from .helper.webRTC_service import (
    check_webrtc_availability,
    create_watch_connection,
    process_ice_candidate,
    process_observer_ice_candidate,
    process_webrtc_offer,
)
from .helper.webSocket_service import (
    handle_stream_connection,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["dashcam"])


@router.post("/refresh", tags=["jwt"])
async def jwt_refresh(
    authorize: AuthJWT = Depends(authentication),  # noqa: B008
) -> JSONResponse:
    await authorize.jwt_refresh_token_required()

    current_user = await authorize.get_jwt_subject()
    raw = await authorize.get_raw_jwt()

    if current_user is None or raw is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        auth_jwt_data: models.AuthJwtData = models.AuthJwtData(**raw)
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from e

    new_access_token = await authorize.create_access_token(
        subject=current_user,
        user_claims=auth_jwt_data.model_dump(),
    )

    await authorize.set_access_cookies(new_access_token)


@router.post("/logout", tags=["jwt"])
async def jwt_logout(
    authorize: AuthJWT = Depends(authentication),  # noqa: B008
    db: DBSession = Depends(get_db_engine),  # noqa: B008
) -> JSONResponse:
    await authorize.jwt_refresh_token_required()
    refresh_token = await authorize.get_raw_jwt()
    revoked_refresh_token = database.RevokedToken.from_token(
        token=refresh_token,
    )
    revoked_refresh_token.add(db=db)

    # Also try to revoke the access token if provided
    with contextlib.suppress(Exception):
        await authorize.jwt_required()
        access_token = await authorize.get_raw_jwt()
        revoked_access_token = database.RevokedToken.from_token(
            token=access_token,
        )
        revoked_access_token.add(db=db)

    await authorize.unset_jwt_cookies()


@router.post(
    "/registration/options",
    tags=["registration"],
)
async def registration_options(
    request: Request,
    data: schemas.PostRegistrationOptionsIn,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
) -> Response:
    database.User.clear_unusable_users(db)

    session_handler: SessionHandler = session.get_session_handler(request)
    await session_handler.destroy()

    user: database.User = database.User(
        email=data.email,
        username=data.username,
        role=data.role,
    )

    try:
        user.add(db=db)
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid user data",
        ) from e
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists",
        ) from e

    public_key: PublicKeyCredentialCreationOptions = (
        lib.WebAuthn.registration_options(
            username=data.email,
        )
    )

    webauthn_challenge: models.WebAuthnChallenge = models.WebAuthnChallenge(
        challenge_b64=base64.b64encode(public_key.challenge).decode(),
        timeout=public_key.timeout,
    )

    session_data: models.SessionDataRegistration = (
        models.SessionDataRegistration(
            user_id_str=str(user.id),
            user_id_webauthn_base64=base64.b64encode(
                public_key.user.id,
            ).decode(),
            webauthn_challenge=webauthn_challenge,
        )
    )

    await load_session(request)
    request.session.update(session_data.model_dump())

    return Response(
        content=options_to_json(public_key),
        media_type="application/json",
    )


@router.post(
    "/registration/verify",
    tags=["registration"],
    response_model=schemas.PostRegistrationVerifyOut,
)
async def registration_verify(
    request: Request,
    data: schemas.PostRegistrationVerifyIn,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    rd: Redis = Depends(get_redis),  # noqa: B008
) -> schemas.PostRegistrationVerifyOut:
    database.User.clear_unusable_users(db)

    await load_session(request)
    session_handler: SessionHandler = session.get_session_handler(request)

    try:
        session_data: models.SessionDataRegistration = (
            models.SessionDataRegistration(**request.session)
        )
    except ValidationError as e:
        await session_handler.destroy()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from e

    await session_handler.destroy()

    try:
        verified_registration: VerifiedRegistration = (
            lib.WebAuthn.registration_verify(
                credential=data.credential,
                webauthn_challenge=session_data.webauthn_challenge,
            )
        )
    except InvalidJSONStructure as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e
    except InvalidRegistrationResponse as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from e

    # Challenge expired
    if verified_registration is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        user: database.User = database.User.get_user_by_id(
            user_id=session_data.user_id,
            db=db,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    webauthn_credential: database.WebAuthn = database.WebAuthn(
        user_id_webauthn=session_data.user_id_webauthn,
        credential_id=verified_registration.credential_id,
        credential_public_key=verified_registration.credential_public_key,
        sign_count=verified_registration.sign_count,
        user_id=user.id,
    )

    master_key = MasterKey(
        id=data.device_id.encode("utf-8"),
        master_key=data.master_key,
        user_id=user.id,
    )

    device = database.Device(
        id=data.device_id.encode("utf-8"),
        pub_key=data.public_key,
        status="approved",
        user_id=user.id,
    )

    try:
        user = user.add_webauthn(webauthn=webauthn_credential, db=db)
        master_key.add_masterkey(masterkey=master_key, db=db)
        device.add_new_device(device=device, db=db)
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
        ) from e

    # Resend
    secret_token, secret_token_hash = utils.generate_secret_token()
    sent: bool = lib.Resend.send_email_verification(
        to=user.email,
        subject="Verification email",
        token=secret_token,
    )

    if not sent:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    await redis.add_email_token(
        redis=rd,
        user_id=user.id,
        token_hash=secret_token_hash,
    )

    # TOTP
    totp: lib.TOTP = lib.TOTP()
    user = user.set_totp_secret(
        secret=totp.secret,
        db=db,
    )

    return schemas.PostRegistrationVerifyOut(
        totp_provisioning_uri=totp.new_totp(email=user.email),
    )


@router.post(
    "/authentication/options",
    tags=["authentication"],
)
async def authentication_options(
    request: Request,
    data: schemas.PostAuthenticationOptionsIn,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
) -> Response:
    database.User.clear_unusable_users(db)

    session_handler: SessionHandler = session.get_session_handler(request)
    await session_handler.destroy()

    user: database.User = database.User.get_user_by_username_and_email(
        username=data.username,
        email=data.email,
        db=db,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    if (
        not user.email_verified
        or not user.webauthn
        or user.totp_secret is None
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    public_key: PublicKeyCredentialRequestOptions = (
        lib.WebAuthn.authentication_options(webauthn_credentials=user.webauthn)
    )

    webauthn_challenge: models.WebAuthnChallenge = models.WebAuthnChallenge(
        challenge_b64=base64.b64encode(public_key.challenge).decode(),
        timeout=public_key.timeout,
    )

    session_data: models.SessionDataAuthentication = (
        models.SessionDataAuthentication(
            user_id_str=str(user.id),
            webauthn_challenge=webauthn_challenge,
        )
    )

    await load_session(request)
    request.session.update(session_data.model_dump())

    return Response(
        content=options_to_json(public_key),
        media_type="application/json",
    )


@router.post(
    "/authentication/verify",
    tags=["authentication"],
)
async def authentication_verify(  # noqa: C901, PLR0912, PLR0913, PLR0915
    request: Request,
    data: schemas.PostAuthenticationVerifyIn,
    x_ssl_client_verify: Annotated[str | None, Header()] = None,
    x_ssl_client_dn: Annotated[str | None, Header()] = None,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication),  # noqa: B008
) -> None:
    # Récupération des informations du client pour les logs
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "inconnu")

    # Log de la tentative d'authentification
    log_service.secure_log(
        message="Tentative d'authentification",
        level="INFO",
        action="authentication_verify",
        ip_address=client_ip,
        user_agent=user_agent,
        method=request.method,
        route=request.url.path,
        data={"timestamp": utils.get_utc_now().isoformat()},
    )

    database.User.clear_unusable_users(db)

    await load_session(request)
    session_handler: SessionHandler = session.get_session_handler(request)

    try:
        session_data: models.SessionDataAuthentication = (
            models.SessionDataAuthentication(**request.session)
        )
    except ValidationError as e:
        await session_handler.destroy()
        # Log de l'échec de validation de session
        log_service.secure_log(
            message="Échec d'authentification: données de session invalides",
            level="WARNING",
            action="authentication_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            error=str(e),
            method=request.method,
            route=request.url.path,
            data={
                "status": "400 Bad Request",
                "reason": "Données de session invalides",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from e

    await session_handler.destroy()

    try:
        user: database.User = database.User.get_user_by_id(
            user_id=session_data.user_id,
            db=db,
        )
    except ValidationError as e:
        # Log de l'échec de récupération utilisateur
        log_service.secure_log(
            message="Échec d'authentification: validation utilisateur échouée",
            level="WARNING",
            action="authentication_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=str(session_data.user_id)
            if session_data.user_id
            else "inconnu",
            error=str(e),
            method=request.method,
            route=request.url.path,
            data={
                "status": "422 Unprocessable Entity",
                "reason": "Validation utilisateur échouée",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e

    if user is None:
        # Log utilisateur non trouvé
        log_service.secure_log(
            message="Échec d'authentification: utilisateur non trouvé",
            level="WARNING",
            action="authentication_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=str(session_data.user_id)
            if session_data.user_id
            else "inconnu",
            method=request.method,
            route=request.url.path,
            data={
                "status": "404 Not Found",
                "reason": "Utilisateur non trouvé",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # mTLS for trusted users
    if user.role == models.UserRole.TRUSTED:
        if not x_ssl_client_verify or not x_ssl_client_dn:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        mtls_verify: lib.MTLSClientVerify = lib.MTLSClientVerify.from_str(
            x_ssl_client_verify,
        )
        if mtls_verify != lib.MTLSClientVerify.SUCCESS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            mtls_client_dn: lib.MTLSClientDistinguishedName = (
                lib.MTLSClientDistinguishedName(
                    data=x_ssl_client_dn,
                )
            )
        except (ValueError, ValidationError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            ) from e

        if user.email != mtls_client_dn.email_address:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

    # TOTP
    try:
        secret: SecretStr = user.get_totp_secret()
    except InvalidTag as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e

    if secret is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    totp: lib.TOTP = lib.TOTP(secret=secret)
    totp_verified: bool = totp.verify_totp(
        otp=data.otp,
    )

    if not totp_verified:
        # Log échec vérification TOTP
        log_service.secure_log(
            message="Échec d'authentification: code TOTP invalide",
            level="WARNING",
            action="authentication_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=str(user.id),
            username=user.username,
            method=request.method,
            route=request.url.path,
            data={
                "status": "401 Unauthorized",
                "reason": "Code TOTP invalide",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # WebAuthn
    raw_id: bytes = utils.decode_credential_id(
        id=data.credential.get("rawId")
        if isinstance(data.credential, dict)
        else data.credential.raw_id,
    )
    webauthn_credential: database.WebAuthn = user.get_webauthn_from_raw_id(
        raw_id=raw_id,
    )

    if webauthn_credential is None:
        # Log credential WebAuthn non trouvé
        log_service.secure_log(
            message="Échec d'authentification: credential WebAuthn non trouvé",
            level="WARNING",
            action="authentication_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=str(user.id),
            username=user.username,
            method=request.method,
            route=request.url.path,
            data={
                "status": "404 Not Found",
                "reason": "Credential WebAuthn non trouvé",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    try:
        verified_authentication: VerifiedAuthentication = (
            lib.WebAuthn.authentication_verify(
                credential=data.credential,
                webauthn_credential=webauthn_credential,
                webauthn_challenge=session_data.webauthn_challenge,
                db=db,
            )
        )
    except InvalidJSONStructure as e:
        # Log structure JSON invalide
        log_service.secure_log(
            message="Échec d'authentification: structure JSON invalide",
            level="WARNING",
            action="authentication_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=str(user.id),
            username=user.username,
            error=str(e),
            method=request.method,
            route=request.url.path,
            data={
                "status": "422 Unprocessable Entity",
                "reason": "Structure JSON invalide",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e
    except InvalidAuthenticationResponse as e:
        # Log réponse d'authentification invalide
        log_service.secure_log(
            message="Échec d'authentification: réponse WebAuthn invalide",
            level="WARNING",
            action="authentication_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=str(user.id),
            username=user.username,
            error=str(e),
            method=request.method,
            route=request.url.path,
            data={
                "status": "401 Unauthorized",
                "reason": "Réponse WebAuthn invalide",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from e

    # Challenge expired
    if verified_authentication is None:
        # Log défi expiré
        log_service.secure_log(
            message="Échec d'authentification: défi WebAuthn expiré",
            level="WARNING",
            action="authentication_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=str(user.id),
            username=user.username,
            method=request.method,
            route=request.url.path,
            data={
                "status": "401 Unauthorized",
                "reason": "Défi WebAuthn expiré",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # Create JWT tokens
    auth_jwt_data: models.AuthJwtData = models.AuthJwtData(role=user.role)
    access_token: str = await authorize.create_access_token(
        subject=str(user.id),
        user_claims=auth_jwt_data.model_dump(),
    )
    refresh_token: str = await authorize.create_refresh_token(
        subject=str(user.id),
        user_claims=auth_jwt_data.model_dump(),
    )

    # Set JWT cookies
    await authorize.set_access_cookies(access_token)
    await authorize.set_refresh_cookies(refresh_token)

    # Log d'authentification réussie
    log_service.secure_log(
        message=f"Authentification réussie pour l'utilisateur {user.username}",
        level="INFO",
        user_id=str(user.id),
        action="authentication_verify",
        ip_address=client_ip,
        user_agent=user_agent,
        role=str(user.role),
        method=request.method,
        route=request.url.path,
        data={
            "status": "200 OK",
            "success_time": utils.get_utc_now().isoformat(),
            "authentication_method": "WebAuthn+TOTP",
        },
    )


@router.get(
    "/email/verify/{token}",
    tags=["email"],
)
async def email_verify(
    request: Request,  # Ajout de l'objet Request pour obtenir les informations client
    token: str,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    rd: Redis = Depends(get_redis),  # noqa: B008
) -> Response:
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "inconnu")

    # Log de la tentative de vérification d'email
    log_service.secure_log(
        message="Tentative de vérification d'email",
        level="INFO",
        action="email_verify",
        ip_address=client_ip,
        user_agent=user_agent,
        method=request.method,
        route=request.url.path,
        token_partial=token[:5]
        + "...",  # On ne log que le début du token pour la sécurité
        data={"timestamp": utils.get_utc_now().isoformat()},
    )

    token_hash: str = utils.generate_token_hash(token)
    user_id: uuid.UUID = await redis.get_user_id_by_email_token(
        redis=rd,
        token_hash=token_hash,
    )

    await redis.delete_email_token(
        redis=rd,
        token_hash=token_hash,
    )

    if user_id is None:
        # Log de token invalide
        log_service.secure_log(
            message="Échec de vérification d'email: token invalide ou expiré",
            level="WARNING",
            action="email_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            method=request.method,
            route=request.url.path,
            token_partial=token[:5] + "...",
            data={
                "status": "404 Not Found",
                "reason": "Token invalide ou expiré",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    user: database.User = database.User.get_user_by_id(
        user_id=user_id,
        db=db,
    )

    if user is None:
        # Log d'utilisateur non trouvé
        log_service.secure_log(
            message="Échec de vérification d'email: utilisateur non trouvé",
            level="WARNING",
            action="email_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            method=request.method,
            route=request.url.path,
            user_id=str(user_id),
            data={
                "status": "404 Not Found",
                "reason": "Utilisateur non trouvé",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    try:
        user.set_verified_email(db=db)

        # Log de vérification réussie
        log_service.secure_log(
            message=f"Vérification d'email réussie pour l'utilisateur {user.username}",
            level="INFO",
            action="email_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=str(user.id),
            username=user.username,
            email=user.email,
            method=request.method,
            route=request.url.path,
            data={
                "status": "200 OK",
                "verification_time": utils.get_utc_now().isoformat(),
            },
        )
    except ValueError as e:
        # Log d'erreur lors de la vérification
        log_service.secure_log(
            message="Échec de vérification d'email: email déjà vérifié",
            level="WARNING",
            action="email_verify",
            ip_address=client_ip,
            user_agent=user_agent,
            user_id=str(user.id),
            username=user.username,
            email=user.email,
            method=request.method,
            route=request.url.path,
            error=str(e),
            data={
                "status": "409 Conflict",
                "reason": "Email déjà vérifié",
                "timestamp": utils.get_utc_now().isoformat(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
        ) from e

    return Response(content="Email verification successful")


@router.post(
    "/totp/regenerate",
    tags=["otp"],
    response_model=schemas.PostRegistrationVerifyOut,
)
async def totp_regenerate(
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_all),  # noqa: B008
) -> schemas.PostRegistrationVerifyOut:
    user_id: str = await authorize.get_jwt_subject()

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user_id: uuid.UUID = uuid.UUID(user_id)

    try:
        user: database.User = database.User.get_user_by_id(
            user_id=user_id,
            db=db,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    if user.totp_secret is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    totp: lib.TOTP = lib.TOTP()
    user = user.set_totp_secret(
        secret=totp.secret,
        db=db,
    )

    return schemas.PostRegistrationVerifyOut(
        totp_provisioning_uri=totp.new_totp(email=user.email),
    )


@router.post(
    "/user/username",
    tags=["user"],
    response_model=schemas.PostRegistrationVerifyOut,
)
async def new_username(
    data: schemas.PostUserUsernameIn,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_all),  # noqa: B008
) -> None:
    user_id: str = await authorize.get_jwt_subject()

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user_id: uuid.UUID = uuid.UUID(user_id)

    try:
        user: database.User = database.User.get_user_by_id(
            user_id=user_id,
            db=db,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    user = user.set_new_username(new_username=data.new_username, db=db)

    return Response()


# Routes WebRTC
@router.post("/webrtc/offer")
async def webrtc_offer(  # noqa: ANN201
    request: Request,
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: ARG001, B008
):
    """Reçoit une offre WebRTC d'un client et répond avec une réponse."""
    body = await request.json()
    return await process_webrtc_offer(
        body["sdp"],
        body["type"],
        body.get("connection_id"),
    )


@router.post("/webrtc/ice_candidate")
async def webrtc_ice_candidate(  # noqa: ANN201
    request: Request,
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: ARG001, B008
):
    """Reçoit un candidat ICE d'un client."""
    body = await request.json()
    return await process_ice_candidate(
        body["connection_id"],
        body["candidate"],
    )


@router.post("/webrtc/watch/{connection_id}")
async def webrtc_watch(  # noqa: ANN201
    request: Request,
    connection_id: str,
    authorize: AuthJWT = Depends(authentication_trusted),  # noqa: ARG001, B008
):
    """Permet à un client de regarder le stream WebRTC d'un autre client."""
    body = await request.json()
    return await create_watch_connection(
        connection_id,
        body["sdp"],
        body["type"],
    )


@router.post("/webrtc/observer/ice_candidate")
async def webrtc_observer_ice_candidate(  # noqa: ANN201
    request: Request,
    authorize: AuthJWT = Depends(authentication_trusted),  # noqa: ARG001, B008
):
    """Reçoit un candidat ICE d'un observateur."""
    body = await request.json()
    return await process_observer_ice_candidate(
        body["connection_id"],
        body["observer_id"],
        body["candidate"],
    )


@router.get("/webrtc/check/{connection_id}")
async def webrtc_check_availability(  # noqa: ANN201
    connection_id: str,
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: ARG001, B008
):
    """Vérifie si un stream a une connexion WebRTC active."""
    return check_webrtc_availability(connection_id)


# Routes WebSocket
@router.websocket("/ws/stream")
async def websocket_stream(
    websocket: WebSocket,
    csrf_token: str = Query(...),  # noqa: ARG001
    authorize: AuthJWT = Depends(authentication_websocket_regular),  # noqa: B008
    db: DBSession = Depends(get_db_engine),  # noqa: B008
) -> None:
    user_id: str = await authorize.get_jwt_subject()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user_id: uuid.UUID = uuid.UUID(user_id)
    """Gère la connexion WebSocket pour recevoir un stream vidéo"""
    await handle_stream_connection(websocket, user_id, db)


# Routes pour les streams actifs et vidéos
@router.get("/streams")
async def list_active_streams(  # noqa: ANN201
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: ARG001, B008
):
    """Liste les streams actuellement actifs."""  # noqa: D401
    log_service.secure_log("Récupération des streams actifs", level="INFO")
    return list_active_streams_data()


@router.get("/videos")
async def list_videos(  # noqa: ANN201
    request: Request,
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
    db: DBSession = Depends(get_db_engine),  # noqa: B008
):
    """Liste les vidéos enregistrées par stream."""  # noqa: D401
    user_id: str = await authorize.get_jwt_subject()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    log_service.secure_log(
        message="Consultation de la liste des vidéos",
        level="INFO",
        user_id=user_id,
        action="list_videos",
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", "inconnu"),
        method=request.method,
        route=request.url.path,
        data={"request_time": datetime.now(timezone.utc).isoformat()},
    )
    user_id: uuid.UUID = uuid.UUID(user_id)

    return list_videos_data(user_id=user_id, db=db)


@router.get("/videos/{video_id}")
async def get_video(  # noqa: ANN201
    request: Request,
    video_id: uuid.UUID,
    authorize: AuthJWT = Depends(authentication_all),  # noqa: B008
    db: DBSession = Depends(get_db_engine),  # noqa: B008
):
    """Récupère et télécharge un fichier JSON spécifique."""
    user_id = await authorize.get_jwt_subject()
    raw = await authorize.get_raw_jwt()

    if user_id is None or raw is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    log_service.secure_log(
        message=f"Accès à la vidéo {video_id}",
        level="INFO",
        user_id=user_id,
        action="get_video",
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", "inconnu"),
        method=request.method,
        route=request.url.path,
        data={
            "video_id": str(video_id),
            "status": "200 OK",
            "access_time": datetime.now(timezone.utc).isoformat(),
        },
    )

    user_id = uuid.UUID(user_id)

    try:
        auth_jwt_data: models.AuthJwtData = models.AuthJwtData(**raw)
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from e

    path: Path = get_video_file(
        user_id=user_id,
        user_role=auth_jwt_data.role,
        video_id=video_id,
        db=db,
        request=request,
    )
    return FileResponse(
        path=path,
        filename=path.name,
        media_type="application/json",
    )


@router.post("/videos/delete/{video_id}")
async def delete_video(  # noqa: ANN201
    request: Request,
    video_id: str,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
):
    """Supprime un fichier vidéo spécifique ou un répertoire entier."""
    user_id: str = await authorize.get_jwt_subject()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    log_service.secure_log(
        message=f"Suppression de la vidéo {video_id}",
        level="WARNING",  # Niveau WARNING car c'est une action destructive
        user_id=user_id,
        action="delete_video",
        ip_address=request.client.host,
        user_agent=request.headers.get("user-agent", "inconnu"),
        method=request.method,
        route=request.url.path,
        data={
            "video_id": video_id,
            "status": "200 OK",
            "deletion_time": datetime.now(timezone.utc).isoformat(),
        },
    )

    user_id: uuid.UUID = uuid.UUID(user_id)
    return delete_video_file(video_id, user_id, db)


@router.post("/dev/stream/key")
async def store_key(  # noqa: ANN201
    request: Request,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
):
    """Stocke une clé de stream dans la base de données."""
    body = await request.json()
    user_id: str = await authorize.get_jwt_subject()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user_id: uuid.UUID = uuid.UUID(user_id)

    stream_key = StreamKey(
        id=uuid.uuid4(),
        encrypted_key=body["encrypted_key"],
        stream_id=body["stream_id"],
        owner_id=user_id,
    )
    StreamKey.add_stream_key(db, stream_key=stream_key)
    return {"status": "ok"}


@router.get("/dev/stream/key")
async def get_key(  # noqa: ANN201
    stream_id: uuid.UUID,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
):
    """Récupère une clé de stream spécifique."""
    # TODO : Ajouter des vérifs pour voir si l'utilisateur est soit owner ou trusted  # noqa: E501
    user_id: str = await authorize.get_jwt_subject()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user_id: uuid.UUID = uuid.UUID(user_id)

    stream_key = StreamKey.get_stream_key(db, stream_id=stream_id)
    if stream_key is None:
        logger.info("Stream key not found for stream_id: %s", stream_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    return {"key": stream_key.encrypted_key}


@router.post("/dev/user/register/masterkey")
async def store_masterkey(  # noqa: ANN201
    request: Request,
    data: schemas.PostMasterKeyIn,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
):
    """Stocke la masterkey dans la base de données."""
    await load_session(request)
    session_handler: SessionHandler = session.get_session_handler(request)

    try:
        session_data: models.SessionDataRegistration = (
            models.SessionDataRegistration(**request.session)
        )
    except ValidationError as e:
        await session_handler.destroy()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from e

    try:
        user: database.User = database.User.get_user_by_id(
            user_id=session_data.user_id,
            db=db,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e

    masterkey = MasterKey(
        id=data.webauthn_cred_id,
        master_key=data.master_key,
        user_id=user.id,
    )

    try:
        masterkey = masterkey.add_masterkey(db, masterkey)
    except ValueError as e:
        log_msg = f"Erreur lors de l'enregistrement de la masterkey : {e}"
        logger.exception(log_msg)

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
        ) from e
    return {
        "id": masterkey.id,
        "message": "Nouvelle masterkey enregistrée avec succès",
    }


@router.post("/dev/user/masterkey")
async def get_master_key(  # noqa: ANN201
    request: Request,  # noqa: ARG001
    data: schemas.GetMasterKeyIn,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_all),  # noqa: B008
):
    """Récupère une masterkey spécifique."""
    user_id: str = await authorize.get_jwt_subject()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user_id: uuid.UUID = uuid.UUID(user_id)

    # Utilisation de la méthode spécifique pour récupérer la masterke
    masterkey = MasterKey.get_masterkey_by_id_and_user(
        db=db,
        masterkey_id=data.device_id.encode("utf8"),
        user_id=user_id,
    )

    if masterkey is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Masterkey non trouvée",
        )

    return {"masterkey": masterkey.master_key}


@router.post("/dev/user/device")
async def get_device(  # noqa: ANN201
    request: Request,  # noqa: ARG001
    data: schemas.GetDeviceIn,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
):
    """Récupère un appareil spécifique."""
    user_id: str = await authorize.get_jwt_subject()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user_id: uuid.UUID = uuid.UUID(user_id)

    device = Device(
        id=data.webauthn_cred_id,
        user_id=user_id,
    )

    device = device.get_device(db, device)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Appareil non trouvé",
        )

    return {"device": device}


@router.delete("/dev/user/masterkey")
async def delete_masterkey(
    request: Request,  # noqa: ARG001
    data: schemas.DeleteMasterKey,  # noqa: ARG001
    db: DBSession = Depends(get_db_engine),  # noqa: ARG001, B008
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
) -> None:
    """Supprime une masterkey de la base de données."""
    user_id: str = await authorize.get_jwt_subject()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user_id: uuid.UUID = uuid.UUID(user_id)


@router.get("/dev/user/pubkey/{email}")
async def get_public_key(
    request: Request,  # noqa: ARG001
    email: EmailStr,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
) -> dict[str, list[tuple[str, str]]]:
    """Récupère une pubkey spécifique."""
    user_id: str = await authorize.get_jwt_subject()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    print(email)

    try:
        user = User.get_user_id_by_email(email, db=db)
        print(user)

        devices_pubkey_list = Device.get_pub_keys_by_user_id(
            user_id=user,
            db=db,
        )
        print(devices_pubkey_list)

        return {"pubkey_list": devices_pubkey_list}
    except ValueError as e:
        print(e)


@router.delete("/dev/user/device")
async def delete_device(  # noqa: ANN201
    request: Request,  # noqa: ARG001
    data: schemas.DeleteDevice,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_all),  # noqa: B008
):
    """Supprime un appareil de la base de données."""
    user_id: str = await authorize.get_jwt_subject()
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user_id: uuid.UUID = uuid.UUID(user_id)

    device = Device(
        id=data.webauthn_cred_id,
        user_id=user_id,
    )

    existing_device = database.Device.get_device(db, device)
    if existing_device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Appareil non trouvé",
        )

    if existing_device.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Vous n'êtes pas autorisé à supprimer cet appareil",
        )

    try:
        database.Device.rm_device(db, device)
        log_msg = (
            f"Appareil supprimé avec succès - ID : {data.webauthn_cred_id}"
        )
        logger.info(log_msg)
    except ValueError as e:
        log_msg = f"Erreur lors de la suppression de l'appareil - ID : {data.webauthn_cred_id}"  # noqa: E501
        logger.exception(log_msg)

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
        ) from e

    return {
        "message": "Appareil supprimé avec succès",
        "id": data.webauthn_cred_id,
    }


@router.post("/device/add_request")
async def add_device_request(  # noqa: ANN201
    request: Request,
    data: schemas.AddDeviceRequest,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    rd: Redis = Depends(get_redis),  # noqa: B008
):
    """Ajoute une demande d'appareil à la base de données."""
    await load_session(request)
    session_handler: SessionHandler = session.get_session_handler(request)

    try:
        session_data: models.SessionDataAuthentication = (
            models.SessionDataAuthentication(**request.session)
        )
    except ValidationError as e:
        log_msg = f"Erreur de validation des données de session : {e}"
        logger.exception(log_msg)

        await session_handler.destroy()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from e

    await session_handler.destroy()

    user = database.User.get_user_by_id(
        user_id=session_data.user_id,
        db=db,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé",
        )

    await redis.handle_add_device_request(
        email=user.email,
        new_device_pk=data.pubkey_device,
        db=db,
        device_id=data.device_id,
        redis=rd,
    )

    return Response(status_code=status.HTTP_200_OK)


@router.get("/device/check_approval/{new_device_temp_id}")
async def check_device_approval(
    request: Request,
    new_device_temp_id: models.Base64Encoded,
    rd: Redis = Depends(get_redis),  # noqa: B008
) -> dict[str, bool]:
    """Vérifie si une demande d'appareil a été approuvée."""
    await load_session(request)
    session_handler: SessionHandler = session.get_session_handler(request)

    try:
        session_data: models.SessionDataAuthentication = (
            models.SessionDataAuthentication(**request.session)
        )
    except ValidationError as e:
        await session_handler.destroy()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from e

    await session_handler.destroy()

    is_approved = await redis.check_device_approval(
        user_id=session_data.user_id,
        device_id=new_device_temp_id,
        redis=rd,
    )

    return {"is_approved": is_approved}


@router.get("/device/requests")
async def get_device_requests(
    rd: Redis = Depends(get_redis),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_all),  # noqa: B008
) -> list:
    """Récupère les demandes d'appareil de l'utilisateur."""
    current_user_id_str = await authorize.get_jwt_subject()
    if current_user_id_str is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    current_user_id = uuid.UUID(current_user_id_str)

    return await redis.get_device_requests(
        user_id=current_user_id,
        redis=rd,
    )


@router.delete("/device/requests")
async def delete_device_request(
    data: schemas.DeleteDeviceRequest,
    rd: Redis = Depends(get_redis),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_all),  # noqa: B008
) -> Response:
    """Supprime une demande d'appareil de Redis."""
    current_user_id_str = await authorize.get_jwt_subject()
    if current_user_id_str is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    current_user_id = uuid.UUID(current_user_id_str)

    await redis.delete_device_request(
        user_id=current_user_id,
        device_id=data.temp_device_id,
        redis=rd,
    )

    return Response(status_code=status.HTTP_200_OK)


@router.post("/device/approve")
async def approve_device_request(
    data: schemas.ApproveDeviceRequest,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    rd: Redis = Depends(get_redis),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_all),  # noqa: B008
) -> Response:
    """Approuve une demande d'appareil."""
    current_user_id_str = await authorize.get_jwt_subject()
    if current_user_id_str is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    current_user_id = uuid.UUID(current_user_id_str)

    user = database.User.get_user_by_id(current_user_id, db=db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Utilisateur non trouvé",
        )

    masterkey = user.masterkey
    if masterkey is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Masterkey non trouvée",
        )

    device = Device(
        id=data.device_id.encode("utf-8"),
        pub_key=data.pubkey,
        user_id=current_user_id,
    )
    try:
        device = Device.add_new_device(db, device)
    except Exception as e:
        log_msg = f"Erreur lors de l'ajout de l'appareil : {e}"
        logger.exception(log_msg)

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
        ) from e

    enc_master_key = EncMasterKey(
        encrypted_master_key=data.encrypted_master_key,
        device_id=device.id,
        master_key_id=masterkey[0].id,
    )
    try:
        enc_master_key.add(db)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
        ) from e

    await redis.approve_device_request(
        user_id=current_user_id,
        device_id=data.device_id,
        redis=rd,
    )

    return Response(status_code=status.HTTP_200_OK)


@router.post("/approved_device/options")
async def approve_device_options(
    request: Request,
    data: schemas.ApproveDeviceOptions,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
) -> Response:
    """Récupère les options pour un appareil approuvé."""
    database.User.clear_unusable_users(db)

    session_handler: SessionHandler = session.get_session_handler(request)
    await session_handler.destroy()

    try:
        user: database.User = database.User.get_user_by_email(
            email=data.email,
            db=db,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid user data",
        ) from e

    public_key: PublicKeyCredentialCreationOptions = (
        lib.WebAuthn.registration_options(
            username=data.email,
        )
    )

    webauthn_challenge: models.WebAuthnChallenge = models.WebAuthnChallenge(
        challenge_b64=base64.b64encode(public_key.challenge).decode(),
        timeout=public_key.timeout,
    )

    session_data: models.SessionDataRegistration = (
        models.SessionDataRegistration(
            user_id_str=str(user.id),
            user_id_webauthn_base64=base64.b64encode(
                public_key.user.id,
            ).decode(),
            webauthn_challenge=webauthn_challenge,
        )
    )

    await load_session(request)
    request.session.update(session_data.model_dump())

    return Response(
        content=options_to_json(public_key),
        media_type="application/json",
    )


@router.post("/approved_device/verify")
async def approve_device_verification(  # noqa: C901
    request: Request,
    data: schemas.ApproveDeviceVerify,
    x_ssl_client_verify: Annotated[str | None, Header()] = None,
    x_ssl_client_dn: Annotated[str | None, Header()] = None,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    rd: Redis = Depends(get_redis),  # noqa: B008
    authorize: AuthJWT = Depends(authentication),  # noqa: B008
) -> None:
    """Enregistre un appareil approuvé."""
    database.User.clear_unusable_users(db)

    await load_session(request)
    session_handler: SessionHandler = session.get_session_handler(request)

    try:
        session_data: models.SessionDataRegistration = (
            models.SessionDataRegistration(**request.session)
        )
    except ValidationError as e:
        await session_handler.destroy()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from e

    await session_handler.destroy()

    try:
        verified_registration: VerifiedRegistration = (
            lib.WebAuthn.registration_verify(
                credential=data.credential,
                webauthn_challenge=session_data.webauthn_challenge,
            )
        )
    except InvalidJSONStructure as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e
    except InvalidRegistrationResponse as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from e

    if verified_registration is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        user: database.User = database.User.get_user_by_id(
            user_id=session_data.user_id,
            db=db,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # mTLS for trusted users
    if user.role == models.UserRole.TRUSTED:
        if not x_ssl_client_verify or not x_ssl_client_dn:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        mtls_verify: lib.MTLSClientVerify = lib.MTLSClientVerify.from_str(
            x_ssl_client_verify,
        )
        if mtls_verify != lib.MTLSClientVerify.SUCCESS:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            mtls_client_dn: lib.MTLSClientDistinguishedName = (
                lib.MTLSClientDistinguishedName(
                    data=x_ssl_client_dn,
                )
            )
        except (ValueError, ValidationError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            ) from e

        if user.email != mtls_client_dn.email_address:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

    # TOTP
    try:
        secret: SecretStr = user.get_totp_secret()
    except InvalidTag as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e

    if secret is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    totp: lib.TOTP = lib.TOTP(secret=secret)
    totp_verified: bool = totp.verify_totp(
        otp=data.otp,
    )

    if not totp_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    # WebAuthn
    webauthn_credential: database.WebAuthn = database.WebAuthn(
        user_id_webauthn=session_data.user_id_str,
        credential_id=verified_registration.credential_id,
        credential_public_key=verified_registration.credential_public_key,
        sign_count=verified_registration.sign_count,
        user_id=user.id,
    )

    if webauthn_credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Create JWT tokens
    auth_jwt_data: models.AuthJwtData = models.AuthJwtData(role=user.role)
    access_token: str = await authorize.create_access_token(
        subject=str(user.id),
        user_claims=auth_jwt_data.model_dump(),
    )
    refresh_token: str = await authorize.create_refresh_token(
        subject=str(user.id),
        user_claims=auth_jwt_data.model_dump(),
    )

    # Set JWT cookies
    await authorize.set_access_cookies(access_token)
    await authorize.set_refresh_cookies(refresh_token)


@router.post("/share/stream", response_model=schemas.SharedStreamOut)
async def share_stream(
    share_data: schemas.ShareStreamIn,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
) -> schemas.SharedStreamOut:
    current_user_id_str = await authorize.get_jwt_subject()
    if current_user_id_str is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    owner_user_id = uuid.UUID(current_user_id_str)

    # Récupérer l'utilisateur propriétaire (celui qui initie le partage)
    owner_user = db.exec(
        select(database.User).where(database.User.id == owner_user_id),
    ).first()
    if not owner_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Owner user not found.",
        )

    # Vérifier que le stream appartient bien à l'utilisateur qui le partage
    if not Stream.exists_and_is_owned_by(
        db,
        share_data.stream_id,
        owner_user.id,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only share your own streams, or stream not found.",
        )

    # Récupérer l'ID de l'utilisateur destinataire par email
    recipient_user = database.User.get_user_id_by_email(
        email=share_data.recipient_email,
        db=db,
    )

    if recipient_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient email not found.",
        )

    # Vérifier que le destinataire n'est pas le propriétaire lui-même
    if recipient_user == owner_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot share a stream with yourself.",
        )

    # Vérifier si le destinataire a le rôle 'trusted'
    is_trusted = database.SharedStream.is_recipient_trusted(
        db,
        recipient_id=recipient_user,
    )
    if not is_trusted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Recipient does not have the required 'trusted' role.",
        )

    # Utiliser la nouvelle méthode pour vérifier si le partage existe déjà
    existing_shared_stream = database.SharedStream.get_existing_shared_stream(
        db,
        owner_id=owner_user.id,
        recipient_id=recipient_user,
        stream_id=share_data.stream_id,
    )

    if existing_shared_stream:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Stream already shared with this recipient.",
        )

    # Créer le nouveau partage de stream
    shared_stream = database.SharedStream(
        stream_id=share_data.stream_id,
        owner_id=owner_user.id,
        recipient_id=recipient_user,
        shared_encryption_key=share_data.shared_encryption_key,
    )
    db.add(shared_stream)
    db.commit()
    db.refresh(shared_stream)
    print(shared_stream)
    return shared_stream

    # Note: La gestion de la clé publique pour le chiffrement sera implémentée ultérieurement ici.  # noqa: E501
    # Pour l'instant, `shared_encryption_key` est stockée telle quelle ou null.

    # return new_shared_stream


@router.get(
    "/shared/streams",
    response_model=list[schemas.SharedStreamOut],
)
async def get_shared_streams(
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_all),  # noqa: B008
) -> list[schemas.SharedStreamOut]:
    user_id = await authorize.get_jwt_subject()
    raw = await authorize.get_raw_jwt()

    if user_id is None or raw is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    user_id = uuid.UUID(user_id)

    try:
        auth_jwt_data: models.AuthJwtData = models.AuthJwtData(**raw)
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from e

    match auth_jwt_data.role:
        case models.UserRole.REGULAR:
            fetch_fn = SharedStream.get_shared_streams_by_owner
        case models.UserRole.TRUSTED:
            fetch_fn = SharedStream.get_shared_streams_for_recipient
        case _:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to access this resource.",
            )

    streams = fetch_fn(db, user_id)
    return [
        schemas.SharedStreamOut(**stream.model_dump()) for stream in streams
    ]


@router.get("/shared/stream/{shared_stream_id}/key/{device_id}")
async def get_shared_stream_key(
    shared_stream_id: uuid.UUID,
    device_id: str,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_trusted),  # noqa: B008
) -> Response:
    user_id: str = await authorize.get_jwt_subject()

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    user_id: uuid.UUID = uuid.UUID(user_id)

    try:
        user: database.User = database.User.get_user_by_id(
            user_id=user_id,
            db=db,
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        ) from e

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    return database.SharedStream.get_shared_stream_key(
        db=db,
        shared_stream_id=shared_stream_id,
        recipient_id=user_id,
        device_id=device_id,
    )


@router.delete(
    "/shared/stream/{shared_stream_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_shared_stream(
    shared_stream_id: uuid.UUID,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
) -> Response:
    """Supprime un partage de stream. Seul le propriétaire du partage peut le supprimer."""  # noqa: E501
    current_user_id_str = await authorize.get_jwt_subject()
    if current_user_id_str is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    current_user_id = uuid.UUID(current_user_id_str)

    shared_stream = SharedStream.get_shared_stream_by_ids(db, shared_stream_id)

    if not shared_stream:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Shared stream not found.",
        )

    if shared_stream.owner_id != current_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to delete this shared stream.",
        )

    if not SharedStream.delete_shared_stream(db, shared_stream_id):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete shared stream.",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Shared Videos ---


@router.post("/share/video", response_model=schemas.ShareVideoOut)
async def share_video(  # noqa: ANN201
    share_data: schemas.ShareVideoIn,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
):
    """Partage une vidéo avec un autre utilisateur via son email."""
    current_user_id_str = await authorize.get_jwt_subject()
    if current_user_id_str is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    owner_user_id = uuid.UUID(current_user_id_str)

    owner_user = db.exec(
        select(database.User).where(database.User.id == owner_user_id),
    ).first()
    if not owner_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Owner user not found.",
        )

    recipient_user = database.User.get_user_id_by_email(
        email=share_data.recipient_email,
        db=db,
    )
    if not recipient_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient user not found.",
        )

    if owner_user.id == recipient_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot share a video with yourself.",
        )

    video = database.Video.get_video_by_id(db, share_data.video_id)
    if not video or video.owner_id != owner_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found or you are not the owner.",
        )

    # Vérifier si le destinataire a le rôle 'trusted'
    is_trusted = database.SharedStream.is_recipient_trusted(
        db,
        recipient_id=recipient_user,
    )
    if not is_trusted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Recipient does not have the required 'trusted' role.",
        )

    # Vérifiez si le partage existe déjà avec la nouvelle méthode
    existing_shared_video = database.SharedVideo.get_existing_shared_video(
        db,
        owner_id=owner_user.id,  # L'ID de l'utilisateur qui partage (owner)
        recipient_id=recipient_user,  # L'ID de l'utilisateur qui reçoit (recipient)  # noqa: E501
        video_id=video.id,  # L'ID de la vidéo partagée
    )

    if existing_shared_video:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Video already shared with this recipient.",
        )

    shared_video = database.SharedVideo(
        owner_id=owner_user.id,
        recipient_id=recipient_user,
        video_id=video.id,
        shared_encryption_key=share_data.shared_encryption_key,
    )
    database.SharedVideo.add_shared_video(db, shared_video)
    return shared_video


@router.get(
    "/shared/videos/{device_id}",
    response_model=list[schemas.SharedVideoOut],
)
async def get_shared_videos(
    device_id: str,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_all),  # noqa: B008
) -> list[schemas.SharedVideoOut]:
    user_id = await authorize.get_jwt_subject()
    raw = await authorize.get_raw_jwt()

    if user_id is None or raw is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    user_id = uuid.UUID(user_id)

    try:
        auth_jwt_data: models.AuthJwtData = models.AuthJwtData(**raw)
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
        ) from e

    match auth_jwt_data.role:
        case models.UserRole.REGULAR:
            fetch_fn = SharedVideo.get_shared_videos_by_owner
        case models.UserRole.TRUSTED:
            fetch_fn = SharedVideo.get_shared_videos_for_recipient
        case _:
            print("1")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to access this resource.",
            )

    videos = fetch_fn(db, user_id)
    if not videos:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No shared videos found.",
        )

    filtered_videos = []
    for video in videos:
        key = None
        if video.shared_encryption_key:
            for k in video.shared_encryption_key:
                if k.get("device_id") == str(device_id):
                    key = k.get("encrypted_key")
                    break
        video_dict = video.model_dump()
        video_dict["shared_encryption_key"] = key
        filtered_videos.append(schemas.SharedVideoOut(**video_dict))

    return filtered_videos


@router.delete(
    "/shared/video/{shared_video_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_shared_video(
    shared_video_id: uuid.UUID,
    db: DBSession = Depends(get_db_engine),  # noqa: B008
    authorize: AuthJWT = Depends(authentication_regular),  # noqa: B008
) -> Response:
    """Supprime un partage de vidéo. Seul le propriétaire du partage peut le supprimer."""  # noqa: E501
    current_user_id_str = await authorize.get_jwt_subject()
    if current_user_id_str is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    current_user_id = uuid.UUID(current_user_id_str)

    shared_video = SharedVideo.get_shared_video_by_ids(db, shared_video_id)

    if not shared_video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Shared video not found.",
        )

    if shared_video.owner_id != current_user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to delete this shared video.",
        )

    if not SharedVideo.delete_shared_video(db, shared_video_id):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete shared video.",
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)

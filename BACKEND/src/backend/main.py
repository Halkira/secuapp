import asyncio
import json
import logging
import re
import secrets
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from re import Pattern

import starsessions
from async_fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from securecookies import SecureCookiesMiddleware
from securecookies.extras.csrf import SecureCSRFMiddleware
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from starsessions import SessionMiddleware
from starsessions.stores.redis import RedisStore

from backend import constants, patch, utils
from backend.config import settings
from backend.database import create_db_and_tables
from backend.log_service import check_log_server_health
from backend.redis import close_redis, get_redis_client, init_redis
from backend.router import router as dashcam_router

logger = logging.getLogger(__name__)

# Patch the session ID generation to generate the value with 64 bytes
# instead of 16 bytes
# https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy
starsessions.session.generate_session_id = lambda: secrets.token_hex(64)

# Patch the "support" of SecureCookiesMiddleware provided
# by SecureCookiesMiddleware
SecureCSRFMiddleware._get_submitted_csrf_token = (  # noqa: SLF001
    patch.get_submitted_csrf_token_patched
)

SecureCSRFMiddleware.__call__ = patch.csrf_middleware_call

pattern_registration_options: Pattern = re.compile(
    rf"^{settings.api_prefix_version}/registration/options/?$",
)
pattern_authentication_options: Pattern = re.compile(
    rf"^{settings.api_prefix_version}/authentication/options/?$",
)
pattern_approved_device_options: Pattern = re.compile(
    rf"^{settings.api_prefix_version}/approved_device/options/?$",
)

pattern_registration_verify: Pattern = re.compile(
    rf"^{settings.api_prefix_version}/registration/verify/?$",
)
pattern_authentication_verify: Pattern = re.compile(
    rf"^{settings.api_prefix_version}/authentication/verify/?$",
)
pattern_approved_device_verify: Pattern = re.compile(
    rf"^{settings.api_prefix_version}/approved_device/verify/?$",
)


# Déplacer et corriger la classe avant son utilisation
class MaintenanceModeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Importer ici pour éviter les imports circulaires
        from backend.log_service import LOG_SERVER_AVAILABLE

        # Vérifier si le serveur est en mode maintenance
        if not LOG_SERVER_AVAILABLE:
            return Response(
                content=json.dumps(
                    {
                        "status": "error",
                        "message": "Le système est actuellement en maintenance. Veuillez réessayer plus tard.",
                    },
                ),
                status_code=503,
                media_type="application/json",
            )

        # Continuer le traitement normal
        return await call_next(request)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None]:
    logger.info("Starting up...")
    create_db_and_tables()
    await init_redis()
    logger.info("Database and Redis initialized.")
    health_check_task = asyncio.create_task(check_log_server_health())

    yield

    health_check_task.cancel()

    logger.info("Shutting down...")
    await close_redis()
    logger.info("Database and Redis connection closed.")


# SecureCSRFMiddleware is only used for the SessionMiddleware.
# The JWT library has its own CSRF protection mechanism.
# See backend/config.py for more information.
middleware: list[Middleware] = [
    Middleware(MaintenanceModeMiddleware),
    Middleware(
        CORSMiddleware,
        allow_origins=constants.ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    ),
    Middleware(
        SecureCookiesMiddleware,
        secrets=[str(settings.secure_cookies_secret)],
        cookie_domain=constants.RP_ID,
        cookie_secure=True,
        cookie_samesite="strict",
    ),
    Middleware(
        utils.SecureCSRFAuthnMiddleware,
    ),
    Middleware(
        utils.SecureCSRFAuthnWebSocketMiddleware,
    ),
    Middleware(
        utils.RemoveCSRFSessionCookieMiddleware,
    ),
    Middleware(
        SecureCSRFMiddleware,
        secret=str(settings.csrf_secret_key),
        required_urls=[
            pattern_registration_verify,
            pattern_authentication_verify,
            pattern_approved_device_verify,
        ],
        exempt_urls=[
            pattern_registration_options,
            pattern_authentication_options,
            pattern_approved_device_options,
        ],
        sensitive_cookies={"session"},
        safe_methods={},
        cookie_name="csrf_session_token",
        cookie_domain=constants.RP_ID,
        cookie_secure=True,
        cookie_samesite="strict",
        header_name="X-CSRF-Session-Token",
    ),
    Middleware(
        SessionMiddleware,
        store=RedisStore(
            connection=get_redis_client(),
            gc_ttl=settings.session_ttl,
        ),
        lifetime=settings.session_ttl,
        cookie_same_site="strict",
        cookie_domain=constants.RP_ID,
    ),
]

app: FastAPI = FastAPI(
    debug=settings.debug_mode,
    title=f"{settings.api_title} - {settings.api_version}",
    middleware=middleware,
    lifespan=lifespan,
)


@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(
    _request: Request,
    exc: AuthJWTException,
) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message},
    )


app.include_router(prefix=settings.api_prefix_version, router=dashcam_router)

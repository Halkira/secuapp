import base64
import contextlib
import re
import secrets
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlencode

from cryptography.fernet import InvalidToken
from fastapi import Request, Response
from pydantic import SecretStr
from securecookies import SecureCookiesMiddleware
from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend import constants, cryptography
from backend.config import settings


def make_expired_cookie_header(
    cookie_name: str,
    domain: str | None = None,
) -> tuple[bytes, bytes]:
    domain = domain or constants.RP_ID
    cookie_template = (
        "{cookie_name}=; Domain={domain}; Path=/; Max-Age=0; "
        "Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; "
        "SameSite=Strict"
    )
    cookie_str = cookie_template.format(cookie_name=cookie_name, domain=domain)
    return (b"set-cookie", cookie_str.encode("utf-8"))


class RemoveCSRFSessionCookieMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        prefix = re.escape(settings.api_prefix_version)

        self.patterns_allow_cookie = [
            re.compile(rf"^{prefix}/registration/options/?$"),
            re.compile(rf"^{prefix}/authentication/options/?$"),
        ]

        self.patterns_set_expired_cookie_on_success = [
            re.compile(rf"^{prefix}/registration/verify/?$"),
            re.compile(rf"^{prefix}/authentication/verify/?$"),
        ]

    def matches_any(self, path: str, patterns: list[re.Pattern]) -> bool:
        return any(p.match(path) for p in patterns)

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        allow_cookie = self.matches_any(path, self.patterns_allow_cookie)
        expire_cookie_if_success = self.matches_any(
            path,
            self.patterns_set_expired_cookie_on_success,
        )

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status = message.get("status", 500)
                headers = message.get("headers", [])

                if allow_cookie:
                    await send(message)
                    return

                headers = [
                    (k, v)
                    for (k, v) in headers
                    if not (
                        k.lower() == b"set-cookie"
                        and v.lower().startswith(b"csrf_session_token=")
                    )
                ]

                if expire_cookie_if_success and 200 <= status < 300:  # noqa: PLR2004
                    headers.append(
                        make_expired_cookie_header(
                            cookie_name="csrf_session_token",
                        ),
                    )
                    headers.append(
                        make_expired_cookie_header(cookie_name="session"),
                    )

                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, send_wrapper)


class SecureCSRFAuthnMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:  # noqa: ANN001
        if not hasattr(self, "_secure_middleware"):
            app = request.scope["app"].middleware_stack
            while not isinstance(app, SecureCookiesMiddleware):
                try:
                    app = app.app
                except AttributeError:
                    raise Exception(  # noqa: B904, TRY002, TRY003
                        "You must use SecureCSRFAuthnMiddleware in conjunction with"  # noqa: E501, EM101
                        " SecureCookiesMiddleware.",
                    )

            self._secure_middleware = app

        csrf_access_token = request.headers.get("X-CSRF-Access-Token")
        csrf_refresh_token = request.headers.get("X-CSRF-Refresh-Token")

        if csrf_access_token:
            with contextlib.suppress(InvalidToken):
                decrypted_access_token = self._secure_middleware.decrypt(
                    csrf_access_token,
                )
                self._secure_middleware.set_header(
                    request=request,
                    header="x-csrf-access-token",
                    value=decrypted_access_token,
                )

        if csrf_refresh_token:
            with contextlib.suppress(InvalidToken):
                decrypted_refresh_token = self._secure_middleware.decrypt(
                    csrf_refresh_token,
                )
                self._secure_middleware.set_header(
                    request=request,
                    header="x-csrf-refresh-token",
                    value=decrypted_refresh_token,
                )

        return await call_next(request)


class SecureCSRFAuthnWebSocketMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self._secure_middleware = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send):  # noqa: ANN204
        if scope["type"] == "websocket":
            if not self._secure_middleware:
                app_stack = scope["app"].middleware_stack
                while not isinstance(app_stack, SecureCookiesMiddleware):
                    try:
                        app_stack = app_stack.app
                    except AttributeError:
                        raise Exception(  # noqa: B904, TRY002, TRY003
                            "SecureCSRFAuthnWebSocketMiddleware must be used with "  # noqa: E501, EM101
                            "SecureCookiesMiddleware",
                        )
                self._secure_middleware = app_stack

            headers = MutableHeaders(scope=scope)
            cookie_header = headers.get("cookie")

            if cookie_header:
                cookie = SimpleCookie()
                cookie.load(cookie_header)
                updated_cookie = {}

                for key, morsel in cookie.items():
                    value = morsel.value
                    if key == "access_token_cookie":
                        with contextlib.suppress(InvalidToken):
                            value = self._secure_middleware.decrypt(value)
                    updated_cookie[key] = value

                new_cookie_header = "; ".join(
                    f"{k}={v}" for k, v in updated_cookie.items()
                )
                headers["cookie"] = new_cookie_header

            raw_qs = scope.get("query_string", b"").decode("utf-8")
            query_params = dict(parse_qsl(raw_qs))

            csrf_token = query_params.get("csrf_token")
            if csrf_token:
                with contextlib.suppress(InvalidToken):
                    query_params["csrf_token"] = (
                        self._secure_middleware.decrypt(csrf_token)
                    )

            scope["query_string"] = urlencode(query_params).encode("utf-8")

        await self.app(scope, receive, send)


def get_utc_now() -> datetime:
    """Get the current UTC time.

    :return: The current UTC time.
    """
    return datetime.now(timezone.utc)


def get_utc_now_milliseconds() -> int:
    """Get the current UTC time in milliseconds.

    :return: The current UTC time in milliseconds.
    """
    return int(get_utc_now().timestamp() * 1000)


def generate_secret_token() -> tuple[SecretStr, str]:
    """Generate a random secret token and its hash.

    :return: A tuple containing the token and its hash.
    """
    token = SecretStr(secrets.token_urlsafe(1024))
    token_hash = generate_token_hash(token.get_secret_value())

    return token, token_hash


def generate_token_hash(token: str) -> str:
    """Hash a token using SHA-256.

    :param token: The token to hash.
    :return: The hashed token.
    """
    return cryptography.computer_hash(token)


def decode_credential_id(id: str) -> bytes:  # noqa: A002
    # Add padding if needed (base64url encoding may omit '=' padding)
    padding = "=" * (-len(id) % 4)
    raw_id_padded = id + padding
    return base64.urlsafe_b64decode(raw_id_padded)

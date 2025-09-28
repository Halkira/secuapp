import functools

from cryptography.fernet import InvalidToken
from fastapi import Request
from securecookies import SecureCookiesMiddleware
from starlette.types import Receive, Scope, Send


async def get_submitted_csrf_token_patched(
    self,  # noqa: ANN001
    request: Request,
) -> str | None:
    if not hasattr(self, "_secure_middleware"):
        app = request.scope["app"].middleware_stack
        while not isinstance(app, SecureCookiesMiddleware):
            try:
                app = app.app
            except AttributeError:
                raise Exception(  # noqa: B904, TRY002, TRY003
                    "You must use SecureCSRFMiddleware in conjunction with"  # noqa: EM101
                    " SecureCookiesMiddleware.",
                )

        self._secure_middleware = app

    csrf_session_token: str = request.headers.get(self.header_name)
    if csrf_session_token is None:
        return None

    try:
        return self._secure_middleware.decrypt(csrf_session_token)
    except InvalidToken:
        return None


async def csrf_middleware_call(
    self,  # noqa: ANN001
    scope: Scope,
    receive: Receive,
    send: Send,
) -> None:
    if scope["type"] != "http":  # pragma: no cover
        await self.app(scope, receive, send)
        return

    request = Request(scope)
    csrf_cookie = request.cookies.get(self.cookie_name)

    if self._url_is_required(request.url) or (
        request.method not in self.safe_methods
        and not self._url_is_exempt(request.url)
        and self._has_sensitive_cookies(request.cookies)
    ):
        submitted_csrf_token = await self._get_submitted_csrf_token(request)
        if (
            not csrf_cookie
            or not submitted_csrf_token
            or not self._csrf_tokens_match(csrf_cookie, submitted_csrf_token)
        ):
            response = self._get_error_response(request)
            await response(scope, receive, send)
            return

    send = functools.partial(self.send, send=send, scope=scope)
    await self.app(scope, receive, send)

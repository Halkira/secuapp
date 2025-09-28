from async_fastapi_jwt_auth import AuthJWT
from async_fastapi_jwt_auth.auth_jwt import AuthJWTBearer
from fastapi import HTTPException, Request, Response, WebSocket, status
from pydantic import ValidationError
from sqlmodel import Session

from backend import database, models
from backend.config import settings
from backend.database.token import RevokedToken


@AuthJWT.load_config
def get_config() -> list[tuple]:
    return settings


@AuthJWT.token_in_denylist_loader
async def check_if_token_in_denylist(decrypted_token: dict) -> bool:
    with Session(database.db_engine) as session:
        return RevokedToken.is_revoked(
            token=decrypted_token,
            db=session,
        )


class __BaseAuthJWTBearer(AuthJWTBearer):
    async def __call__(  # noqa: PLR0913
        self,
        req: Request = None,
        res: Response = None,
        auth_from: str | None = "request",
        websocket: WebSocket | None = None,
        csrf_token: str | None = None,
        role: models.UserRole | None = None,
    ) -> AuthJWT:
        auth = super().__call__(req=req, res=res)

        await auth.jwt_required(
            auth_from=auth_from,
            websocket=websocket,
            csrf_token=csrf_token,
        )

        raw = await auth.get_raw_jwt()
        if raw is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            auth_jwt_data: models.AuthJwtData = models.AuthJwtData(**raw)
        except ValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            ) from e

        if role is not None and auth_jwt_data.role != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
            )

        return auth


class AuthJWTBearerAll(__BaseAuthJWTBearer):
    async def __call__(
        self,
        req: Request = None,
        res: Response = None,
    ) -> AuthJWT:
        return await super().__call__(
            req=req,
            res=res,
            auth_from="request",
            websocket=None,
            csrf_token=None,
            role=None,
        )


class AuthJWTBearerRegular(__BaseAuthJWTBearer):
    async def __call__(
        self,
        req: Request = None,
        res: Response = None,
    ) -> AuthJWT:
        return await super().__call__(
            req=req,
            res=res,
            auth_from="request",
            websocket=None,
            csrf_token=None,
            role=models.UserRole.REGULAR,
        )


class AuthJWTBearerTrusted(__BaseAuthJWTBearer):
    async def __call__(
        self,
        req: Request = None,
        res: Response = None,
    ) -> AuthJWT:
        return await super().__call__(
            req=req,
            res=res,
            auth_from="request",
            websocket=None,
            csrf_token=None,
            role=models.UserRole.TRUSTED,
        )


class AuthJWTBearerWebsocketAll(__BaseAuthJWTBearer):
    async def __call__(
        self,
        websocket: WebSocket,
        csrf_token: str,
        req: Request = None,
        res: Response = None,
    ) -> AuthJWT:
        return await super().__call__(
            req=req,
            res=res,
            auth_from="websocket",
            websocket=websocket,
            csrf_token=csrf_token,
            role=None,
        )


class AuthJWTBearerWebsocketRegular(__BaseAuthJWTBearer):
    async def __call__(
        self,
        websocket: WebSocket,
        csrf_token: str,
        req: Request = None,
        res: Response = None,
    ) -> AuthJWT:
        return await super().__call__(
            req=req,
            res=res,
            auth_from="websocket",
            websocket=websocket,
            csrf_token=csrf_token,
            role=models.UserRole.REGULAR,
        )


class AuthJWTBearerWebsocketTrusted(__BaseAuthJWTBearer):
    async def __call__(
        self,
        websocket: WebSocket,
        csrf_token: str,
        req: Request = None,
        res: Response = None,
    ) -> AuthJWT:
        return await super().__call__(
            req=req,
            res=res,
            auth_from="websocket",
            websocket=websocket,
            csrf_token=csrf_token,
            role=models.UserRole.TRUSTED,
        )


# For low level auth management. DO NOT USE ON PROTECTED ENDPOINTS
authentication = AuthJWTBearer()
# Required ALL authenticated users
authentication_all = AuthJWTBearerAll()
authentication_websocket_all = AuthJWTBearerWebsocketAll()
# Require authenticated REGULAR users
authentication_regular = AuthJWTBearerRegular()
authentication_websocket_regular = AuthJWTBearerWebsocketRegular()
# Require authenticated TRUSTED users
authentication_trusted = AuthJWTBearerTrusted()
authentication_websocket_trusted = AuthJWTBearerWebsocketTrusted()

import logging

import uvicorn

from backend import constants

logger = logging.getLogger(__name__)


def run() -> None:
    logger.warning("Running in debug mode. Do not use in production.")
    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=constants.Port.BACKEND,
        reload=True,
        ssl_keyfile="https/backend.key",
        ssl_certfile="https/backend.pem",
    )


if __name__ == "__main__":
    run()

import logging
import os
import sys

import requests


class FailSafeHTTPHandler(logging.Handler):
    def __init__(self, url: str):
        super().__init__()
        self.url = url

    def emit(self, record: logging.LogRecord):
        try:
            response = requests.post(
                self.url,
                json={
                    "message": record.getMessage(),
                    "level": record.levelname,
                },
                timeout=3,
            )
            if not response.ok:
                raise RuntimeError("Failed to send log to server")
        except Exception as e:
            print(f"[ERROR] Log transmission failed: {e}", file=sys.stderr)
            print(
                "[FATAL] Shutting down backend due to logging failure.",
                file=sys.stderr,
            )
            os._exit(1)


# logger.setLevel(logging.INFO)
logger.addHandler(FailSafeHTTPHandler("https://localhost:8001/logs"))

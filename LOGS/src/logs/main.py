from fastapi import FastAPI

from logs.router import router

app = FastAPI(
    title="Secure Logs API",
    description="API sécurisée pour la gestion des logs",
    version="1.0.0",
)

app.include_router(router)


def run() -> None:
    import uvicorn

    uvicorn.run(
        "logs.main:app",
        host="127.0.0.1",
        port=8001,
        reload=True,
        ssl_keyfile="httpslogs.key",
        ssl_certfile="httpslogs.pem",
    )


if __name__ == "__main__":
    run()

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8100,
        reload=True,
        ssl_keyfile="https/backend.key",
        ssl_certfile="https/backend.pem"
    )
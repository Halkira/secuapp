from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import shutil
import subprocess
import re

from starlette.middleware.cors import CORSMiddleware

from send_email import send_cert_email
from pydantic import EmailStr
app = FastAPI()

PENDING_DIR = Path("user_certs/pending")
REFUSED_DIR = Path("user_certs/refused")
SIGNED_DIR = Path("user_certs/signed")
REVOKED_DIR = Path("user_certs/revoked")
TMP_DIR = Path("user_certs/tmp")

CA_KEY_PATH = Path("ca/intermediate/private/interCA.key")
CA_CERT_PATH = Path("ca/intermediate/certs/interCA.pem")
OPENSSL_CNF_PATH = Path("ca/intermediate/openssl.cnf")
CRL_PATH = Path("ca/intermediate/crl/interCA.crl")
ROOTCRL_PATH = Path("ca/root/crl/rootCA.crl")
CA_CHAIN_CRL_PATH = Path("ca/intermediate/crl/ca-chain.crl")

for d in [PENDING_DIR, REFUSED_DIR, SIGNED_DIR, REVOKED_DIR, TMP_DIR]:
    d.mkdir(parents=True, exist_ok=True)

app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://localhost:5175", "https://127.0.0.1:5175","https://localhost:5173"],
        allow_credentials=True,
        allow_methods=["POST","DELETE","GET"],
        allow_headers=["*"],
    )

#app.mount("/Home", StaticFiles(directory="frontend/build", html=True), name="frontend")

@app.post("/sign-csr")
def sign_csr(email: EmailStr = Form(...)):
    csr_path = PENDING_DIR / f"{email}.csr"
    if not csr_path.exists():
        raise HTTPException(status_code=404, detail="CSR not found")

    signed_cert_path = SIGNED_DIR / f"{email}.pem"

    try:
        subprocess.run([
            "openssl", "ca",
            "-config", str(OPENSSL_CNF_PATH),
            "-in", str(csr_path),
            "-out", str(signed_cert_path),
            "-extensions", "usr_cert",
            "-batch"
        ], check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"OpenSSL signing error: {e}")

    csr_path.unlink(missing_ok=True)

    success = send_cert_email(to=email, cert_path=str(signed_cert_path))
    if not success:
        raise HTTPException(status_code=500, detail="Certificat signé mais échec de l'envoi de l'e-mail.")

    return {"message": f"CSR signé, certificat envoyé à {email}"}

@app.post("/submit-csr")
async def submit_csr(file: UploadFile = File(...)):
    tmp_csr_path = TMP_DIR / file.filename
    with open(tmp_csr_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    print(tmp_csr_path)

    result = subprocess.run(
        ["openssl", "req", "-in", str(tmp_csr_path), "-noout", "-subject"],
        capture_output=True,
        text=True,
        check=True
    )

    subject_line = result.stdout.strip()

    match = re.search(r"emailAddress\s*=\s*([\w\.-]+@[\w\.-]+)", subject_line)
    if not match:
        raise ValueError("Adresse e-mail non trouvée dans le CSR.")
    email = match.group(1)

    final_path = PENDING_DIR / f"{email}.csr"
    shutil.move(str(tmp_csr_path), str(final_path))

    return {"message": "CSR received", "email": email}

@app.get("/pending-csrs")
def list_pending_csrs():
    csrs = []
    for csr_file in PENDING_DIR.glob("*.csr"):
        try:
            result = subprocess.run(
                ["openssl", "req", "-in", str(csr_file), "-noout", "-subject"],
                capture_output=True, text=True, check=True
            )
            subject_line = result.stdout.strip()
            subject_str = subject_line[len("subject= "):] if subject_line.startswith("subject= ") else subject_line

            subject_parts = subject_str.strip('/').split('/')
            subject = {}
            for part in subject_parts:
                if '=' in part:
                    k, v = part.split('=', 1)
                    subject[k] = v

            csrs.append({"contact": csr_file.stem, "subject": subject})

        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Error reading CSR {csr_file.name}: {e}")

    return csrs

@app.get("/signed-pem")
def list_signed_pem():
    return [f.stem for f in SIGNED_DIR.glob("*.pem")]

@app.get("/revoked-pem")
def list_revoked_pem():
    return [f.stem for f in REVOKED_DIR.glob("*.pem")]

@app.get("/refused-csrs")
def list_refused_csrs():
    return [f.stem for f in REFUSED_DIR.glob("*.csr")]

@app.post("/refused")
def refuse_pending_csr(email: str):
    csr_path = PENDING_DIR / f"{email}.csr"
    if not csr_path.exists():
        raise HTTPException(status_code=404, detail="CSR not found")

    refused_csr_path = REFUSED_DIR / f"{email}.csr"
    shutil.move(str(csr_path), str(refused_csr_path))

    return {"message": f"CSR {email} moved to refused directory."}

@app.delete("/revoke-signed")
def revoke_signed_cert(email: str):
    signed_cert_path = SIGNED_DIR / f"{email}.pem"
    if not signed_cert_path.exists():
        raise HTTPException(status_code=404, detail="Signed certificate not found")

    try:
        subprocess.run([
            "openssl", "ca",
            "-config", str(OPENSSL_CNF_PATH),
            "-revoke", str(signed_cert_path),
            "-batch"
        ], check=True)

        subprocess.run([
            "openssl", "ca",
            "-config", str(OPENSSL_CNF_PATH),
            "-gencrl",
            "-out", str(CRL_PATH)
        ], check=True)

        if ROOTCRL_PATH.exists() and CRL_PATH.exists():
            root_crl_bytes = ROOTCRL_PATH.read_bytes()
            inter_crl_bytes = CRL_PATH.read_bytes()
            CA_CHAIN_CRL_PATH.write_bytes(root_crl_bytes + inter_crl_bytes)
        else:
            raise HTTPException(status_code=500, detail="Root or Intermediate CRL missing")

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la révocation du certificat: {e}")

    revoked_cert_path = REVOKED_DIR / f"{email}.pem"
    shutil.move(str(signed_cert_path), str(revoked_cert_path))

    return {"message": f"Certificat signé pour {email} a été révoqué et CRL mise à jour."}

@app.get("/crl")
def get_crl():
    if not CA_CHAIN_CRL_PATH.exists():
        raise HTTPException(status_code=404, detail="CRL not found")
    return FileResponse(str(CA_CHAIN_CRL_PATH), media_type="application/pkix-crl")
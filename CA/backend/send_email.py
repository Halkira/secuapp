import logging
import base64
import resend
from pydantic import EmailStr
from settings import settings
import os

logger = logging.getLogger(__name__)

resend.api_key = settings.resend_api_key

def send_cert_email(to: EmailStr, cert_path: str) -> bool:
    try:
        with open(cert_path, "rb") as f:
            cert_bytes = f.read()
    except FileNotFoundError:
        logger.warning(f"Certificat introuvable : {cert_path}")
        return False

    file_name = os.path.basename(cert_path)
    cert_base64 = base64.b64encode(cert_bytes).decode("ascii")

    params = {
        "from": settings.resend_api_email,
        "to": [to],
        "subject": "Votre certificat signé est prêt",
        "html": f"""
        <p>Bonjour,</p>
        <p>Votre certificat a été signé avec succès.</p>
        <p>Vous trouverez en pièce jointe votre certificat.</p>
        <p>Merci d'utiliser notre service.</p>
        <p>L'équipe SecuApp</p>
        """,
        "attachments": [
            {
                "filename": file_name,
                "content": cert_base64,
                "type": "application/x-x509-ca-cert",
                "encoding": "base64",
            }
        ]
    }

    try:
        email = resend.Emails.send(params=params)
        logger.info(f"Email envoyé avec ID : {email.get('id')}")
        return True
    except Exception as e:
        logger.warning(f"Erreur lors de l'envoi du mail : {e}")
        return False
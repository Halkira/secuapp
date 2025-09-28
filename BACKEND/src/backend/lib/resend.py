import logging

import resend
from pydantic import EmailStr, SecretStr

from backend import constants
from backend.config import settings

logger = logging.getLogger(__name__)

resend.api_key = settings.resend_api_key.get_secret_value()


class Resend:
    @classmethod
    def send_email_verification(
        cls,
        to: EmailStr,
        subject: str,
        token: SecretStr,
    ) -> bool:
        # TODO: Change the URL
        token_url: str = f"{constants.Origin.BACKEND}{settings.api_prefix_version}/email/verify/{token.get_secret_value()}"

        body: str = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
            <meta charset="UTF-8">
            <title>Verify Your Email</title>
            </head>
            <body style="background-color: #f4f4f4; margin: 0; padding: 0; font-family: Arial, sans-serif;">
            <div style="background-color: #ffffff; margin: 30px auto; padding: 20px; max-width: 600px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
                <h2>Welcome to Our Service!</h2>
                <p>Thank you for signing up. Please verify your email address by clicking the button below:</p>
                <a href="{token_url}" style="display: inline-block; padding: 12px 20px; margin-top: 20px; background-color: #4CAF50; color: #ffffff; text-decoration: none; border-radius: 5px; font-size: 16px;">Verify Email</a>
                <p>If the button doesn't work, copy and paste the following link into your browser:</p>
                <p><a href="{token_url}">{token_url}</a></p>
                <div style="margin-top: 30px; font-size: 12px; color: #888888; text-align: center;">
                <p>If you did not create an account, you can safely ignore this email.</p>
                </div>
            </div>
            </body>
            </html>
        """  # noqa: E501

        params = resend.Emails.SendParams = {
            "from": settings.resend_api_email,
            "to": [to],
            "subject": subject,
            "html": body,
        }

        try:
            email: resend.Email = resend.Emails.send(params=params)
        except Exception as e:  # noqa: BLE001
            msg: str = f"Error sending email: {e}"
            logger.warning(msg)
            return False

        msg: str = f"Email sent: {email.get('id')}"
        logger.info(msg)
        return True

import webauthn
from pydantic import (
    EmailStr,
)
from webauthn.authentication.verify_authentication_response import (
    VerifiedAuthentication,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticationCredential,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    PublicKeyCredentialRequestOptions,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import (
    VerifiedRegistration,
)

from backend import database, models
from backend.constants import RP_ID, RP_NAME, RP_ORIGINS


class WebAuthn:
    @classmethod
    def registration_options(
        cls,
        username: EmailStr,
        user_id: bytes | None = None,
        exclude_credential: list[PublicKeyCredentialDescriptor] | None = None,
    ) -> PublicKeyCredentialCreationOptions:
        public_key: PublicKeyCredentialCreationOptions = (
            webauthn.generate_registration_options(
                rp_id=RP_ID,
                rp_name=RP_NAME,
                user_name=username,
                user_id=user_id,
                attestation=AttestationConveyancePreference.DIRECT,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    require_resident_key=True,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
                exclude_credentials=exclude_credential,
                hints=[PublicKeyCredentialHint.CLIENT_DEVICE],
            )
        )

        return public_key

    @classmethod
    def registration_verify(
        cls,
        credential: str | dict | RegistrationCredential,
        webauthn_challenge: models.WebAuthnChallenge,
    ) -> VerifiedRegistration | None:
        # pem_root_certs_bytes_by_fmt parameter is not used but exists
        registration_verification: VerifiedRegistration = (
            webauthn.verify_registration_response(
                credential=credential,
                expected_challenge=webauthn_challenge.challenge,
                expected_rp_id=RP_ID,
                expected_origin=RP_ORIGINS,
                require_user_presence=True,
                require_user_verification=True,
            )
        )

        # Still go through the verification process even if the challenge
        # is expired, useful for the response verification code
        if webauthn_challenge.is_expired:
            return None

        return registration_verification

    @classmethod
    def authentication_options(
        cls,
        webauthn_credentials: list[database.WebAuthn],
    ) -> PublicKeyCredentialRequestOptions:
        allow_credentials: list[PublicKeyCredentialDescriptor] = [
            PublicKeyCredentialDescriptor(
                id=credential.credential_id,
                transports=[AuthenticatorTransport.INTERNAL],
            )
            for credential in webauthn_credentials
        ]

        public_key: PublicKeyCredentialRequestOptions = (
            webauthn.generate_authentication_options(
                rp_id=RP_ID,
                allow_credentials=allow_credentials,
                user_verification=UserVerificationRequirement.REQUIRED,
            )
        )

        return public_key

    @classmethod
    def authentication_verify(
        cls,
        credential: str | dict | AuthenticationCredential,
        webauthn_credential: database.WebAuthn,
        webauthn_challenge: models.WebAuthnChallenge,
        db: database.Session,
    ) -> VerifiedAuthentication | None:
        authentication_verification: VerifiedAuthentication = webauthn.verify_authentication_response(  # noqa: E501
            credential=credential,
            expected_challenge=webauthn_challenge.challenge,
            expected_rp_id=RP_ID,
            expected_origin=RP_ORIGINS,
            credential_public_key=webauthn_credential.credential_public_key,
            credential_current_sign_count=webauthn_credential.sign_count,
            require_user_verification=True,
        )

        webauthn_credential.update_sign_count(
            new_sign_count=authentication_verification.new_sign_count,
            db=db,
        )

        if webauthn_challenge.is_expired:
            return None

        return authentication_verification

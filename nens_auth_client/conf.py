# -*- coding: utf-8 -*-
from appconf import AppConf


class NensAuthClientAppConf(AppConf):
    SCOPE = ["openid", "email", "profile"]
    STANDALONE = False
    URL_NAMESPACE = "nens_auth_client:"  # prefixed to viewnames in reverse()
    TIMEOUT = 10  # Timeout for token, JWKS and discovery requests (seconds)
    LEEWAY = 120  # Amount of seconds that a token's expiry can be off

    DEFAULT_SUCCESS_URL = "/"  # Default redirect after successful login
    DEFAULT_LOGOUT_URL = "/"  # Default redirect after successful logout

    RESOURCE_SERVER_ID = None  # For Access Tokens ("aud" should equal this)

    PERMISSION_BACKEND = "nens_auth_client.permissions.DjangoPermissionBackend"

    INVITATION_EMAIL_SUBJECT = "Invitation"
    INVITATION_EXPIRY_DAYS = 14  # change this to change the default expiry

    ERROR_USER_DOES_NOT_EXIST = "No user account available for these credentials."
    ERROR_USER_INACTIVE = "This account was set to inactive."
    ERROR_INVITATION_DOES_NOT_EXIST = "The invitation does not exist."
    ERROR_INVITATION_UNUSABLE = "The invitation has been used already."
    ERROR_INVITATION_EXPIRED = "The invitation has expired."
    ERROR_INVITATION_WRONG_USER = "This invitation was not intended for the current user."
    ERROR_INVITATION_WRONG_EMAIL = ERROR_INVITATION_WRONG_USER

    class Meta:
        prefix = "NENS_AUTH"
        required = (
            "CLIENT_ID",  # Provided by AWS Cognito
            "CLIENT_SECRET",  # Provided by AWS Cognito
            "ISSUER",  # N&S Global (authorization server URL)
        )

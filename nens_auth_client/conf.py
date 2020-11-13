# -*- coding: utf-8 -*-
from appconf import AppConf


class NensAuthClientAppConf(AppConf):
    SCOPE = ["openid", "email", "profile"]
    STANDALONE = False
    URL_NAMESPACE = "nens_auth_client:"  # prefixed to viewnames in reverse()
    AUTO_CREATE_REMOTE_USER = True
    TIMEOUT = 10  # Timeout for token, JWKS and discovery requests (seconds)
    LEEWAY = 120  # Amount of seconds that a token's expiry can be off

    DEFAULT_SUCCESS_URL = "/"  # Default redirect after successful login
    DEFAULT_LOGOUT_URL = "/"  # Default redirect after successful logout

    RESOURCE_SERVER_ID = None  # For Access Tokens ("aud" should equal this)

    ASSIGN_PERMISSIONS = "nens_auth_client.models.assign_permissions"
    VALIDATE_PERMISSIONS = "nens_auth_client.models.validate_permissions"

    class Meta:
        prefix = "NENS_AUTH"
        required = (
            "CLIENT_ID",  # Provided by AWS Cognito
            "CLIENT_SECRET",  # Provided by AWS Cognito
            "ISSUER",  # N&S Global (authorization server URL)
        )

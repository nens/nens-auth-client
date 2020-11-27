# -*- coding: utf-8 -*-
from appconf import AppConf


class NensAuthClientAppConf(AppConf):
    SCOPE = ["openid", "email", "profile"]
    STANDALONE = False
    URL_NAMESPACE = "nens_auth_client:"  # prefixed to viewnames in reverse()
    TIMEOUT = 10  # Timeout for token, JWKS and discovery requests (seconds)
    LEEWAY = 120  # Amount of seconds that a token's expiry can be off
    USERNAME_CLAIM = "cognito:username"  # The ID token claim that matches the Django username

    DEFAULT_SUCCESS_URL = "/"  # Default redirect after successful login
    DEFAULT_LOGOUT_URL = "/"  # Default redirect after successful logout

    RESOURCE_SERVER_ID = None  # For Access Tokens ("aud" should equal this)

    PERMISSION_BACKEND = "nens_auth_client.permissions.DjangoPermissionBackend"

    class Meta:
        prefix = "NENS_AUTH"
        required = (
            "CLIENT_ID",  # Provided by AWS Cognito
            "CLIENT_SECRET",  # Provided by AWS Cognito
            "ISSUER",  # N&S Global (authorization server URL)
        )

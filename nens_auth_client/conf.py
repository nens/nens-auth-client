# -*- coding: utf-8 -*-
from appconf import AppConf


class NensAuthClientAppConf(AppConf):
    SCOPE = ["openid", "email", "profile"]
    STANDALONE = False
    AUTO_CREATE_REMOTE_USER = True
    TIMEOUT = 10  # Timeout for token, JWKS and discovery requests (seconds)
    LEEWAY = 120  # Amount of seconds that a token's expiry can be off
    TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_basic"

    DEFAULT_SUCCESS_URL = "/"  # Default redirect after successful login
    DEFAULT_LOGOUT_URL = "/"  # Default redirect after successful logout

    RESOURCE_SERVER_ID = None  # For Access Tokens ("aud" should equal this)
    PREPROCESS_ACCESS_TOKEN = "nens_auth_client.cognito.preprocess_access_token"

    class Meta:
        prefix = "NENS_AUTH"
        required = (
            "CLIENT_ID",  # Provided by AWS Cognito
            "CLIENT_SECRET",  # Provided by AWS Cognito
            "LOGOUT_URL",  # N&S Global (full URL ending with /logout)
            "ISSUER",  # N&S Global (authorization server URL)
        )

# -*- coding: utf-8 -*-
from appconf import AppConf


class NensAuthClientAppConf(AppConf):
    SCOPE = "openid email profile"  # phone / user profile admin could be added
    STANDALONE = False
    AUTO_CREATE_REMOTE_USER = True

    DEFAULT_SUCCESS_URL = "/"  # Default redirect after successful login
    DEFAULT_LOGOUT_URL = "/"  # Default redirect after successful logout

    RESOURCE_SERVER_ID = None  # For Access Tokens ("aud" should equal this)
    PREPROCESS_ACCESS_TOKEN = "nens_auth_client.cognito.preprocess_access_token"

    class Meta:
        prefix = "NENS_AUTH"
        required = (
            "CLIENT_ID",  # Provided by AWS Cognito
            "CLIENT_SECRET",  # Provided by AWS Cognito
            "REDIRECT_URI",  # Depends on the urls.py of your django site
            "LOGOUT_REDIRECT_URI",  # Depends on the urls.py of your django site
            "ACCESS_TOKEN_URL",  # N&S Global (full URL ending with /token)
            "AUTHORIZE_URL",  # N&S Global (full URL ending with /authorize)
            "LOGOUT_URL",  # N&S Global (full URL ending with /logout)
            "ISSUER",  # N&S Global (authorization server URL)
            "JWKS_URI",  # N&S Global (full URL ending with /jwks.json)
        )

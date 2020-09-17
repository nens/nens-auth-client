# -*- coding: utf-8 -*-
from appconf import AppConf


class NensAuthClientAppConf(AppConf):
    SCOPE = "openid email profile"  # phone / user profile admin could be added

    STANDALONE = False

    class Meta:
        prefix = "NENS_AUTH"
        required = (
            "CLIENT_ID",  # Provided by AWS Cognito
            "CLIENT_SECRET",  # Provided by AWS Cognito
            "REDIRECT_URI",  # Depends on the urls.py of your django site
            "ACCESS_TOKEN_URL",  # N&S Global (full URL ending with /token)
            "AUTHORIZE_URL",  # N&S Global (full URL ending with /authorize)
            "JWKS_URI",  # N&S Global (full URL ending with /jwks.json)
        )

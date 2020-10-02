# -*- coding: utf-8 -*-
from django.apps import AppConfig
from django.conf import settings
from nens_auth_client.oauth import oauth_registry


class NensAuthClientConfig(AppConfig):
    name = "nens_auth_client"
    verbose_name = "N&S authentication client"

    def ready(self):
        # Register the AWS Cognito client
        oauth_registry.register(
            name="cognito",
            client_id=settings.NENS_AUTH_CLIENT_ID,
            client_secret=settings.NENS_AUTH_CLIENT_SECRET,
            access_token_url=settings.NENS_AUTH_ACCESS_TOKEN_URL,
            access_token_params=None,
            authorize_url=settings.NENS_AUTH_AUTHORIZE_URL,
            authorize_params=None,
            jwks_uri=settings.NENS_AUTH_JWKS_URI,
            issuer=settings.NENS_AUTH_ISSUER,
            client_kwargs={"scope": settings.NENS_AUTH_SCOPE},
        )
        return super().ready()

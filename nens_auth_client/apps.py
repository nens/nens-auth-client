# -*- coding: utf-8 -*-
from django.apps import AppConfig
from nens_auth_client.oauth import get_or_create_client


class NensAuthClientConfig(AppConfig):
    name = "nens_auth_client"
    verbose_name = "N&S authentication client"

    def ready(self):
        # Perform system checks
        from nens_auth_client import checks  # NOQA
        # Register the AWS Cognito client
        get_or_create_client()
        return super().ready()

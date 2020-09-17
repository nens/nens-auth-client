# -*- coding: utf-8 -*-
from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

# We need to import the AppConf here to load the contained default settings:
from nens_auth_client.conf import NensAuthClientAppConf  # NOQA


class NensAuthClientConfig(AppConfig):
    name = "nens_auth_client"
    verbose_name = "N&S authentication client"

    def ready(self):
        for name in (
            "NENS_AUTH_CLIENT_ID",
            "NENS_AUTH_CLIENT_SECRET",
            "NENS_AUTH_REDIRECT_URI",
        ):
            if not getattr(settings, name):
                raise ImproperlyConfigured(
                    f"nens_auth_client requires the setting {name}"
                )
        return super().ready()

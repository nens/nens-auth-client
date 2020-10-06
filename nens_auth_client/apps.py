# -*- coding: utf-8 -*-
from django.apps import AppConfig


class NensAuthClientConfig(AppConfig):
    name = "nens_auth_client"
    verbose_name = "N&S authentication client"

    def ready(self):
        # Perform system checks
        from nens_auth_client import checks  # NOQA

        return super().ready()

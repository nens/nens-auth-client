# -*- coding: utf-8 -*-
from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

class NensAuthClientConfig(AppConfig):
    name = "nens_auth_client"
    verbose_name = "N&S authentication client"

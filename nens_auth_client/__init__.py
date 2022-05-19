from django import VERSION


if VERSION[0] < 4:
    default_app_config = "nens_auth_client.apps.NensAuthClientConfig"

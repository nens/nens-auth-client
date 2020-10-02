from django.conf import settings
from django.core.checks import Error
from django.core.checks import register


ACCESS_TOKEN_MIDDLWARE = "nens_auth_client.middleware.AccessTokenMiddleware"
DJANGO_AUTH_MIDDLEWARE = "django.contrib.auth.middleware.AuthenticationMiddleware"


@register()
def check_resource_server_id(app_configs=None, **kwargs):
    """Check NENS_AUTH_RESOURCE_SERVER_ID is None or ends with a slash"""
    if ACCESS_TOKEN_MIDDLWARE not in settings.MIDDLEWARE:
        return []
    url = settings.NENS_AUTH_RESOURCE_SERVER_ID
    if url is None:
        return [
            Error(
                "The setting NENS_AUTH_RESOURCE_SERVER_ID is required when "
                "AccessTokenMiddleware is used."
            )
        ]
    if not url.endswith("/"):
        return [
            Error(
                "The NENS_AUTH_RESOURCE_SERVER_ID setting needs to end with a "
                "slash (because AWS Cognito will automatically add one)."
            )
        ]
    return []


@register()
def check_access_token_middleware_order(app_configs=None, **kwargs):
    """Check if AccessTokenMiddleware is after AuthenticationMiddleware"""
    mw = settings.MIDDLEWARE
    if ACCESS_TOKEN_MIDDLWARE not in mw:
        return []
    if DJANGO_AUTH_MIDDLEWARE not in mw or (
        mw.index(ACCESS_TOKEN_MIDDLWARE) < mw.index(DJANGO_AUTH_MIDDLEWARE)
    ):
        return [
            Error(
                "The AccessTokenMiddleware requires to be installed after "
                "authentication middleware. Edit your MIDDLEWARE setting to "
                "insert '{}' before '{}'.".format(
                    DJANGO_AUTH_MIDDLEWARE, ACCESS_TOKEN_MIDDLWARE
                )
            )
        ]
    return []

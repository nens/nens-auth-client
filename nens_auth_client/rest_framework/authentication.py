from rest_framework import exceptions
from django.utils.translation import gettext_lazy as _
from nens_auth_client.oauth import get_oauth_client
from django.contrib.auth.models import AnonymousUser
from authlib.jose.errors import JoseError
from django.conf import settings
import django.contrib.auth as django_auth


class OAuth2Token(dict):
    def __init__(self, scope):
        self.scope = scope


class AccessTokenAuthentication:
    """OAuth2 access token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Bearer ".  For example:

        Authorization: Bearer 401f7ac837da42b97f613d789819ff93537bee6a    
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def authenticate(self, request):
        # See https://tools.ietf.org/html/rfc6750#section-2.1,
        # Bearer is case-sensitive and there is exactly 1 separator after.
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header[7:] if auth_header.startswith("Bearer") else None

        # Do something only if there is a Bearer token
        if not token:
            return (AnonymousUser(), None)

        client = get_oauth_client()
        try:
            claims = client.parse_access_token(token, leeway=settings.NENS_AUTH_LEEWAY)
        except JoseError:
            raise exceptions.AuthenticationFailed("Invalid Bearer token.")

        # The django authentication backend(s) should find a local user
        user = django_auth.authenticate(request, claims=claims)

        if user is None:
            raise exceptions.AuthenticationFailed("User not found.")

        return (user, OAuth2Token(claims["scope"]))

import django.contrib.auth as django_auth
from authlib.jose.errors import JoseError
from django.conf import settings
from rest_framework import exceptions
from rest_framework import HTTP_HEADER_ENCODING

from nens_auth_client.oauth import get_oauth_client


class OAuth2Token(dict):
    @property
    def scope(self):
        return self["scope"]


def get_authorization_header(request):
    """
    Return request's 'Authorization:' header, as a bytestring.

    Hide some test client ickyness where the header can be unicode.
    """
    auth = request.META.get("HTTP_AUTHORIZATION", b"")
    if isinstance(auth, str):
        # Work around django test client oddness
        auth = auth.encode(HTTP_HEADER_ENCODING)
    return auth


class OAuth2TokenAuthentication:
    """OAuth2 access token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Bearer ".  For example:

        Authorization: Bearer 401f7ac837da42b97f613d789819ff93537bee6a

    IMPORTANT: When using this as an authentication_class, the permission classes
    should consistently include `request.auth.scope` in their check.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        # Note: this method is a copy from rest_framework.TokenAuthentication
        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth) == 1:
            msg = "Invalid token header. No credentials provided."
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = "Invalid token header. Token string should not contain spaces."
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()
        except UnicodeError:
            msg = "Invalid token header. Token string should not contain invalid characters."
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(request, token)

    def authenticate_credentials(self, request, token):
        # Same logic as in middleware
        client = get_oauth_client()
        try:
            claims = client.parse_access_token(token, leeway=settings.NENS_AUTH_LEEWAY)
        except JoseError:
            raise exceptions.AuthenticationFailed("Invalid Bearer token.")

        # The django authentication backend(s) should find a local user
        user = django_auth.authenticate(request, claims=claims)

        if user is None:
            raise exceptions.AuthenticationFailed("User not found.")

        return (user, OAuth2Token(claims))

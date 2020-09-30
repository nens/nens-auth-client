from .backends import create_remoteuser
from authlib.jose import jwt
from authlib.jose.errors import JoseError
from django.conf import settings

import django.contrib.auth as django_auth
import requests


def decode_token(token):
    """Decode and validate an ID or Access token and return its payload.

    Args:
      token (str): JWT as a base64-encoded string

    Returns:
      claims (dict or None): the token payload

    Raises:
      authlib.jose.errors.JoseError if token is invalid
    """
    jwks = requests.get(settings.NENS_AUTH_JWKS_URI)
    claims = jwt.decode(
        token,
        jwks.json(),
        claims_options={
            "iss": {"essential": True, "value": settings.NENS_AUTH_ISSUER},
            "aud": {"essential": True, "value": settings.NENS_AUTH_CLIENT_ID},
            "sub": {"essential": True},
        },
    )
    claims.validate()
    return dict(claims)


class OAuth2TokenMiddleware:
    """Middleware for user authentication with OAuth2 Bearer tokens

    The Bearer token is gotten from the Authorization request header as
    specified by https://tools.ietf.org/html/rfc6750#section-2.1

    Use this middleware *after* the AuthenticationMiddleware.

    If there is already a user set (probably via a session cookie), the Bearer
    token is ignored.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        assert hasattr(request, "user"), (
            "The OAuth2TokenMiddleware middleware requires authentication "
            "middleware to be installed. Edit your MIDDLEWARE setting to "
            "insert 'django.contrib.auth.middleware.AuthenticationMiddleware'"
            "before 'nens_auth_client.middleware.OAuth2TokenMiddleware'."
        )
        # Do something only if there is a Bearer token AND there is no user.
        if not (
            request.META.get("HTTP_AUTHORIZATION", "").startswith("Bearer")
            and (not hasattr(request, "user") or request.user.is_anonymous)
        ):
            return self.get_response(request)

        # See https://tools.ietf.org/html/rfc6750#section-2.1,
        # Bearer is case-sensitive and there is exactly 1 seperator after.
        token = request.META["HTTP_AUTHORIZATION"][7:]
        try:
            claims = decode_token(token)
        except JoseError:
            # do nothing
            return self.get_response(request)

        # The django authentication backend(s) should find a local user
        user = django_auth.authenticate(request, claims=claims)

        if user is None:
            # do nothing
            return self.get_response(request)

        # Log the user in
        request.user = user

        # Create a permanent association between local and external users
        if settings.NENS_AUTH_AUTO_CREATE_REMOTE_USER:
            create_remoteuser(user, claims)

        return self.get_response(request)

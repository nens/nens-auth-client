from .backends import create_remoteuser
from .oauth import decode_access_token
from authlib.jose.errors import JoseError
from django.conf import settings

import django.contrib.auth as django_auth


class AccessTokenMiddleware:
    """Middleware for user authentication with OAuth2 Bearer tokens

    Use this middleware *after* the AuthenticationMiddleware.

    If there is already a user set (probably via a session cookie), the Bearer
    token is ignored.

    Any authorization logic based on the "scope" claim should be implemented
    based on ``request.user.oauth2_scope`` (which is set by this middleware).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # See https://tools.ietf.org/html/rfc6750#section-2.1,
        # Bearer is case-sensitive and there is exactly 1 separator after.
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header[7:] if auth_header.startswith("Bearer") else None

        # Do something only if there is a Bearer token and there is no user.
        if not (token and request.user.is_anonymous):
            return self.get_response(request)

        try:
            claims = decode_access_token(token)
        except JoseError:
            # do nothing: not authenticating will lead to a 401 eventually
            return self.get_response(request)

        # The django authentication backend(s) should find a local user
        user = django_auth.authenticate(request, claims=claims)

        if user is None:
            # do nothing: not authenticating will lead to a 401 eventually
            return self.get_response(request)

        # Log the user in (without creating a session)
        request.user = user

        # Store the scope on the user object for later usage
        request.user.oauth2_scope = claims.get("scope")

        # Create a permanent association between local and external users
        if settings.NENS_AUTH_AUTO_CREATE_REMOTE_USER:
            create_remoteuser(user, claims)

        return self.get_response(request)

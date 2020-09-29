from django.contrib.auth import authenticate
from authlib.jose import jwt
from django.conf import settings
import requests
from authlib.jose.errors import JoseError


def verify_token(token):
    jwks = requests.get(settings.NENS_AUTH_JWKS_URI)
    try:
        claims = jwt.decode(
            token,
            jwks.json(),
            claims_options={
                "iss": {
                    "essential": True,
                    "value": settings.NENS_AUTH_ISSUER
                },
                "aud": {
                    "essential": True,
                    "value": settings.NENS_AUTH_CLIENT_ID
                },
                "sub": {
                    "essential": True
                },
            }
        )
        claims.validate()
    except JoseError:
        return
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
        # do something only if request contains a Bearer token
        assert hasattr(request, 'user'), (
            "The OAuth2TokenMiddleware middleware requires authentication "
            "middleware to be installed. Edit your MIDDLEWARE setting to "
            "insert 'django.contrib.auth.middleware.AuthenticationMiddleware'"
            "before 'nens_auth_client.middleware.OAuth2TokenMiddleware'."
        )
        if (
            request.META.get("HTTP_AUTHORIZATION", "").startswith("Bearer")
            and (not hasattr(request, "user") or request.user.is_anonymous)
        ):
            userinfo = verify_token(request.META["HTTP_AUTHORIZATION"][7:])
            if userinfo:
                user = authenticate(request=request, userinfo=userinfo)
                if user:
                    request.user = user

        return self.get_response(request)

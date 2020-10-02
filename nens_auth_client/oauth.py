from authlib.integrations.django_client import OAuth
from authlib.jose import jwt
from django.conf import settings
from django.utils.module_loading import import_string

import requests


# Create the global OAuth registry
oauth_registry = OAuth()


def decode_access_token(token):
    """Decode and validate an access token and return its payload.

    Args:
      token (str): JWT as a base64-encoded string

    Returns:
      claims (dict): the token payload

    Raises:
      authlib.jose.errors.JoseError: if token is invalid
      ValueError: if the key id is not present in the jwks.json
    """
    # TODO Cache this
    jwks = requests.get(settings.NENS_AUTH_JWKS_URI)

    # Decode the token (adding "claims_options" already for later validation)
    claims = jwt.decode(
        token,
        jwks.json(),
        claims_options={
            "aud": {"essential": True, "value": settings.NENS_AUTH_RESOURCE_SERVER_ID},
            "iss": {"essential": True, "value": settings.NENS_AUTH_ISSUER},
            "sub": {"essential": True},
            "scope": {"essential": True},
        },
    )

    # Preprocess the token (to get it into an RFC compliant format)
    if settings.NENS_AUTH_PREPROCESS_ACCESS_TOKEN:
        func = import_string(settings.NENS_AUTH_PREPROCESS_ACCESS_TOKEN)
        func(claims)

    # Validate the token and return
    claims.validate(leeway=120)  # leeway matches authlib's implementation
    return dict(claims)

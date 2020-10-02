from authlib.integrations.django_client import OAuth
from authlib.jose import jwt
from authlib.oidc.discovery import get_well_known_url, OpenIDProviderMetadata
from django.conf import settings
from django.utils.module_loading import import_string

import requests

# Create the global OAuth registry
oauth_registry = OAuth()


def get_oauth_client():
    client = oauth_registry.create_client("cognito")
    if client is None:
        return discover_client()


def discover_client():
    # Generate the autodiscovery url (<iss>/.well-known/openid-configuration)
    url = get_well_known_url(settings.NENS_AUTH_ISSUER, external=True)

    # Get the configuration dict and validate it
    response = requests.get(url, timeout=settings.NENS_AUTH_TIMEOUT)
    response.raise_for_status()

    # Check if the configuration is RFC8414 compliant
    provider = OpenIDProviderMetadata(response.json())
    provider.validate()

    # Check if the our configuration is correct
    assert provider["issuer"] == settings.NENS_AUTH_ISSUER
    unsupported_scopes = set(settings.NENS_AUTH_SCOPE) - set(provider["scopes_supported"])
    assert not unsupported_scopes
    assert "code" in provider["response_types_supported"]
    assert settings.NENS_AUTH_TOKEN_ENDPOINT_AUTH_METHOD in provider["token_endpoint_auth_methods_supported"]

    # Register the AWS Cognito client
    return oauth_registry.register(
        name="cognito",
        client_id=settings.NENS_AUTH_CLIENT_ID,
        client_secret=settings.NENS_AUTH_CLIENT_SECRET,
        access_token_url=provider["token_endpoint"],
        access_token_params=None,
        authorize_url=provider["authorization_endpoint"],
        authorize_params=None,
        jwks_uri=provider["jwks_uri"],
        issuer=settings.NENS_AUTH_ISSUER,
        client_kwargs={"scope": " ".join(settings.NENS_AUTH_SCOPE)},
        token_endpoint_auth_method=settings.NENS_AUTH_TOKEN_ENDPOINT_AUTH_METHOD,
    )


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
    claims.validate(leeway=settings.NENS_AUTH_LEEWAY)
    return dict(claims)

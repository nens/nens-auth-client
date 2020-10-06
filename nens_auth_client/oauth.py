from authlib.integrations.django_client import OAuth
from authlib.oidc.discovery import get_well_known_url
from django.conf import settings
from nens_auth_client.cognito import CognitoOAuthClient


# Create the global OAuth registry
oauth_registry = OAuth()


def get_oauth_client():
    client = oauth_registry.create_client("cognito")
    if client is not None:
        return client

    url = get_well_known_url(settings.NENS_AUTH_ISSUER, external=True)
    oauth_registry.register(
        name="cognito",
        client_id=settings.NENS_AUTH_CLIENT_ID,
        client_secret=settings.NENS_AUTH_CLIENT_SECRET,
        server_metadata_url=url,
        client_kwargs={"scope": " ".join(settings.NENS_AUTH_SCOPE)},
        client_cls=CognitoOAuthClient,
    )
    return oauth_registry.create_client("cognito")

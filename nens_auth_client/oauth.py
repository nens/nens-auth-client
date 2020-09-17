from authlib.integrations.django_client import OAuth
from django.conf import settings

oauth = OAuth()
oauth.register(
    name="cognito",
    client_id=settings.NENS_AUTH_CLIENT_ID,
    client_secret=settings.NENS_AUTH_CLIENT_SECRET,
    access_token_url=settings.NENS_AUTH_ACCESS_TOKEN_URL,
    access_token_params=None,
    authorize_url=settings.NENS_AUTH_AUTHORIZE_URL,
    authorize_params=None,
    jwks_uri=settings.NENS_AUTH_JWKS_URI,
    client_kwargs={"scope": settings.NENS_AUTH_SCOPE},
)

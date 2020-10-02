from authlib.integrations.django_client import OAuth
from authlib.jose import JsonWebToken, jwk
from authlib.oidc.discovery import get_well_known_url
from django.conf import settings
from django.utils.module_loading import import_string
from authlib.integrations.django_client import DjangoRemoteApp

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


class CognitoOAuthClient(DjangoRemoteApp):
    def parse_access_token(self, token, claims_options=None, leeway=120):
        """Decode and validate an access token and return its payload.

        Note: this function is based on DjangoRemoteApp._parse_id_token to
        make use of the same server settings and key cache.

        Args:
          token (str): access token (base64 encoded JWT)

        Returns:
          claims (dict): the token payload

        Raises:
          authlib.jose.errors.JoseError: if token is invalid
          ValueError: if the key id is not present in the jwks.json
        """
        # this is a copy from the _parse_id_token equivalent function
        def load_key(header, payload):
            jwk_set = self.fetch_jwk_set()
            try:
                return jwk.loads(jwk_set, header.get('kid'))
            except ValueError:
                # re-try with new jwk set
                jwk_set = self.fetch_jwk_set(force=True)
                return jwk.loads(jwk_set, header.get('kid'))

        metadata = self.load_server_metadata()
        claims_options = {
            "aud": {"essential": True, "value": settings.NENS_AUTH_RESOURCE_SERVER_ID},
            "iss": {"essential": True, "value": metadata['issuer']},
            "sub": {"essential": True},
            "scope": {"essential": True},
            **(claims_options or {})
        }

        alg_values = metadata.get('id_token_signing_alg_values_supported')
        if not alg_values:
            alg_values = ['RS256']

        claims = JsonWebToken(alg_values).decode(
            token,
            key=load_key,
            claims_options=claims_options,
        )

        # Preprocess the token (to get it into an RFC compliant format)
        if settings.NENS_AUTH_PREPROCESS_ACCESS_TOKEN:
            func = import_string(settings.NENS_AUTH_PREPROCESS_ACCESS_TOKEN)
            func(claims)

        claims.validate(leeway=leeway)
        return claims

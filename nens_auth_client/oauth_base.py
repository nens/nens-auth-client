from authlib.integrations.django_client import DjangoOAuth2App
from authlib.jose import JsonWebKey
from authlib.jose import JsonWebToken
from django.conf import settings


class BaseOAuthClient(DjangoOAuth2App):
    def logout_redirect(self, request, redirect_uri=None, login_after=False):
        """Create a redirect to the remote server's logout endpoint

        Note that unlike with login, there is no standardization for logout.
        This function should be written for a specific authorization server.

        Args:
          request: The current request
          redirect_uri: The absolute url to the logout success view of this app
          login_after: whether to show the login screen after logout

        Returns:
          HttpResponseRedirect authorization server logout endpoint
        """
        raise NotImplementedError()

    def load_key(self, header, payload):
        """Load a JSONWebKey from the authorization server given JWT header and payload.

        Source:
          authlib.integrations.base_client.sync_openid.parse_id_token
        """
        jwk_set = JsonWebKey.import_key_set(self.fetch_jwk_set())
        try:
            return jwk_set.find_by_kid(header.get("kid"))
        except ValueError:
            # re-try with new jwk set
            jwk_set = JsonWebKey.import_key_set(self.fetch_jwk_set(force=True))
            return jwk_set.find_by_kid(header.get("kid"))

    def preprocess_access_token(self, claims):
        """Convert access token claims to standard form, inplace.

        Args:
          claims (dict): payload of the Access Token
        """

    def parse_access_token(self, token, claims_options=None, leeway=120):
        """Decode and validate an access token and return its payload.

        Args:
          token (str): access token (base64 encoded JWT)

        Returns:
          claims (dict): the token payload

        Raises:
          authlib.jose.errors.JoseError: if token is invalid
          ValueError: if the key id is not present in the jwks.json
        """
        metadata = self.load_server_metadata()
        claims_options = {
            "aud": {"essential": True, "value": settings.NENS_AUTH_RESOURCE_SERVER_ID},
            "iss": {"essential": True, "value": metadata["issuer"]},
            "sub": {"essential": True},
            "scope": {"essential": True},
            **(claims_options or {}),
        }

        alg_values = metadata.get("id_token_signing_alg_values_supported")
        if not alg_values:
            alg_values = ["RS256"]

        claims = JsonWebToken(alg_values).decode(
            token, key=self.load_key, claims_options=claims_options
        )

        # Preprocess the token (to add the "aud" claim)
        self.preprocess_access_token(claims)

        claims.validate(leeway=leeway)
        return claims

    @staticmethod
    def extract_provider_name(claims):
        """Return provider name from claim and `None` if not found"""
        # Also used by backends.py
        raise NotImplementedError()

    @staticmethod
    def extract_username(claims) -> str:
        """Return username from claims"""
        # Also used by backends.py
        raise NotImplementedError()

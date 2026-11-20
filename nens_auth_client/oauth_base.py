from authlib.integrations.django_client import DjangoOAuth2App
from django.conf import settings
from joserfc import jwk
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError


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
        jwk_set = jwk.KeySet.import_key_set(self.fetch_jwk_set())
        try:
            return jwk_set.get_by_kid(header.get("kid"))
        except InvalidKeyIdError:
            # re-try with new jwk set
            jwk_set = jwk.KeySet.import_key_set(self.fetch_jwk_set(force=True))
            return jwk_set.get_by_kid(header.get("kid"))

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
          joserfc.errors.JoseError: if token is invalid
          joserfc.errors.InvalidKeyIdError: if the key id is not present in the jwks.json
        """
        metadata = self.load_server_metadata()

        aud_key = (
            "values"
            if isinstance(settings.NENS_AUTH_RESOURCE_SERVER_ID, list)
            else "value"
        )
        claims_options = {
            "aud": {"essential": True, aud_key: settings.NENS_AUTH_RESOURCE_SERVER_ID},
            "iss": {"essential": True, "value": metadata["issuer"]},
            "sub": {"essential": True},
            "scope": {"essential": True},
            **(claims_options or {}),
        }

        alg_values = metadata.get("id_token_signing_alg_values_supported")
        if not alg_values:
            alg_values = ["RS256"]

        def resolve_key(token):
            return self.load_key(token.headers(), None)

        claims = jwt.decode(token, key=resolve_key, algorithms=alg_values).claims

        # Preprocess the token (to add the "aud" claim)
        self.preprocess_access_token(claims)

        claims_registry = jwt.JWTClaimsRegistry(leeway=leeway, **claims_options)
        claims_registry.validate(claims)
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

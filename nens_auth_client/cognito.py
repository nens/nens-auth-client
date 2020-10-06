from django.conf import settings
from authlib.jose import JsonWebToken
from authlib.jose import jwk
from authlib.integrations.django_client import DjangoRemoteApp
from django.http.response import HttpResponseRedirect
from urllib.parse import urlparse
from urllib.parse import urlunparse
from urllib.parse import urlencode


def preprocess_access_token(claims):
    """Convert AWS Cognito Access token claims to standard form, inplace.

    AWS Cognito Access tokens are missing the "aud" (audience) claim and
    instead put the audience into each scope.

    This function filters the scopes on those that start with the
    NENS_AUTH_RESOURCE_SERVER_ID setting. If there is any matching scope, the
    "aud" claim will be set.

    The resulting "scope" has no audience(s) in it anymore.

    Args:
      claims (dict): payload of the Access Token

    Example:
    >>> audience = "https://some/api/"
    >>> claims = {
        "scope": "https://some/api/users.readwrite https://something/else"
    }
    >>> preprocess_access_token(claims)
    >>> claims
    {
        "aud": "https://some/api/",
        "scopes": "users.readwrite",
        ...
    }
    """
    # Do nothing if there is an already an "aud" claim
    if "aud" in claims:
        return

    # Get the expected "aud" claim
    audience = settings.NENS_AUTH_RESOURCE_SERVER_ID

    # List scopes and chop off the audience from the scope
    new_scopes = []
    for scope_item in claims.get("scope", "").split(" "):
        if scope_item.startswith(audience):
            scope_without_audience = scope_item[len(audience) :]
            new_scopes.append(scope_without_audience)

    # Don't set the audience if there are no scopes as Access Token is
    # apparently not meant for this server.
    if not new_scopes:
        return

    # Update the claims inplace
    claims["aud"] = audience
    claims["scope"] = " ".join(new_scopes)


class CognitoOAuthClient(DjangoRemoteApp):
    def logout_redirect(self, request, logout_uri=None):
        """Create a redirect to the remote server's logout endpoint

        Note: unlike with login, there is no standardization on the logout
        endpoint. This function is specifically written for the AWS Cognito
        LOGOUT endpoint. The LOGOUT url is constructed from the AUTHORIZATION
        url.
        """
        # Get the logout endpoint URL from the authorization endpoint
        server_metadata = self.load_server_metadata()
        auth_url = urlparse(server_metadata["authorization_endpoint"])
        logout_url = urlunparse(
            (
                auth_url.scheme,
                auth_url.netloc,
                "logout",
                urlencode({"client_id": self.client_id, "logout_uri": logout_uri}),
                None,
                None,
            )
        )
        return HttpResponseRedirect(logout_url)

    def parse_access_token(self, token, claims_options=None, leeway=120):
        """Decode and validate an access token and return its payload.

        Note: this function is based on authlib.DjangoRemoteApp._parse_id_token
        to make use of the same server settings and key cache. The token claims
        are AWS Cognito specific.

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
                return jwk.loads(jwk_set, header.get("kid"))
            except ValueError:
                # re-try with new jwk set
                jwk_set = self.fetch_jwk_set(force=True)
                return jwk.loads(jwk_set, header.get("kid"))

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
            token, key=load_key, claims_options=claims_options
        )

        # Preprocess the token (to add the "aud" claim)
        preprocess_access_token(claims)

        claims.validate(leeway=leeway)
        return claims

from authlib.integrations.django_client import DjangoOAuth2App
from authlib.jose import JsonWebToken
from authlib.jose import jwk
from django.conf import settings
from django.http.response import HttpResponseRedirect
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.parse import urlunparse


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


class CognitoOAuthClient(DjangoOAuth2App):
    def logout_redirect(self, request, redirect_uri=None, login_after=False):
        """Create a redirect to the remote server's logout endpoint

        Note that unlike with login, there is no standardization for logout.
        This function is specifically written for the AWS Cognito logout
        endpoint. The LOGOUT url is constructed from the AUTHORIZATION url.

        Args:
          request: The current request
          redirect_uri: The absolute url to the logout view of this app. It
            should be pre-registered in AWS Cognito
          login_after: whether to show the login screen after logout

        Returns:
          HttpResponseRedirect to AWS Cognito logout endpoint
        """
        # AWS LOGOUT endpoint accepts the same query params as the authorize
        # endpoint. If this feature is used, you see the login screen after
        # logging out.
        if login_after:
            response = self.authorize_redirect(request, redirect_uri)
            # patch the url
            auth_url = list(urlparse(response.url))
            auth_url[2] = "/logout"  # replace /oauth2/authorize with /logout
            logout_url = urlunparse(auth_url)
        else:
            server_metadata = self.load_server_metadata()
            auth_url = list(urlparse(server_metadata["authorization_endpoint"]))
            auth_url[2] = "/logout"
            auth_url[4] = urlencode(
                {"client_id": self.client_id, "logout_uri": redirect_uri}
            )
            logout_url = urlunparse(auth_url)

        return HttpResponseRedirect(logout_url)

    def parse_access_token(self, token, claims_options=None, leeway=120):
        """Decode and validate a Cognito access token and return its payload.

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

    def validate_authorize_request_params(self, query_params):
        """Returns a list of validation errors"""
        result = []
        if query_params.get("error"):
            return result
        if not query_params.get("code"):
            result.append("missing 'code' parameter")
        if not query_params.get("state"):
            result.append("missing 'state' parameter")
        return result

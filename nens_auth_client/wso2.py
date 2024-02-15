from authlib.integrations.django_client import DjangoOAuth2App
from authlib.jose import JsonWebKey
from authlib.jose import JsonWebToken
from django.http.response import HttpResponseRedirect
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.parse import urlunparse


class WSO2AuthClient(DjangoOAuth2App):
    def logout_redirect(self, request, redirect_uri=None, login_after=False):
        """Create a redirect to the remote server's logout endpoint

        Note that unlike with login, there is no standardization for logout.
        This function is specifically written for the WSO2 logout
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
            auth_url[2] = "/oidc/logout"  # replace /oauth2/authorize with /logout
            logout_url = urlunparse(auth_url)
        else:
            server_metadata = self.load_server_metadata()
            auth_url = list(urlparse(server_metadata["authorization_endpoint"]))
            auth_url[2] = "/oidc/logout"
            auth_url[4] = urlencode(
                {"client_id": self.client_id, "post_logout_redirect_uri": redirect_uri}
            )
            logout_url = urlunparse(auth_url)

        return HttpResponseRedirect(logout_url)

    def parse_access_token(self, token, claims_options=None, leeway=120):
        # this is a copy from the _parse_id_token equivalent function
        def load_key(header, payload):
            jwk_set = self.fetch_jwk_set()
            kid = header.get("kid")
            try:
                return JsonWebKey.import_key_set(jwk_set).find_by_kid(kid)
            except ValueError:
                # re-try with new jwk set
                jwk_set = self.fetch_jwk_set(force=True)
                return JsonWebKey.import_key_set(jwk_set).find_by_kid(kid)

        metadata = self.load_server_metadata()
        claims_options = {
            "iss": {"essential": True, "value": metadata["issuer"]},
            "sub": {"essential": True},
            **(claims_options or {}),
        }

        alg_values = metadata.get("id_token_signing_alg_values_supported")
        if not alg_values:
            alg_values = ["RS256"]

        claims = JsonWebToken(alg_values).decode(
            token, key=load_key, claims_options=claims_options
        )

        claims.validate(leeway=leeway)
        return claims

    def extract_provider_name(self, claims):
        """Return provider name from claim and `None` if not found"""
        return None

    def extract_username(self, claims) -> str:
        """Return username from claims"""
        return claims["email"]

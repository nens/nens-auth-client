from .oauth_base import BaseOAuthClient
from django.conf import settings
from django.http.response import HttpResponseRedirect
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.parse import urlunparse


class CognitoOAuthClient(BaseOAuthClient):
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

    def preprocess_access_token(self, claims):
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

    @staticmethod
    def extract_provider_name(claims):
        """Return provider name from claim and `None` if not found"""
        # Also used by backends.py
        try:
            return claims["identities"][0]["providerName"]
        except (KeyError, IndexError):
            return

    @staticmethod
    def extract_username(claims) -> str:
        """Return username from claims"""
        username = ""
        if claims.get("identities"):
            # External identity providers result in usernames that are not
            # recognizable by the end user. Use the email instead.
            username = claims.get("email")
        if not username:
            username = claims["cognito:username"]
        return username

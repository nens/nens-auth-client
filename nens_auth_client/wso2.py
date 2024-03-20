from .oauth_base import BaseOAuthClient
from django.http.response import HttpResponseRedirect
from urllib.parse import urlencode
from urllib.parse import urlparse
from urllib.parse import urlunparse


class WSO2AuthClient(BaseOAuthClient):
    def logout_redirect(self, request, redirect_uri=None, login_after=False):
        """Create a redirect to the remote server's logout endpoint

        Note that unlike with login, there is no standardization for logout.
        This function is specifically written for the WSO2 logout
        endpoint. The LOGOUT url is constructed from the AUTHORIZATION url.

        Args:
          request: The current request
          redirect_uri: The absolute url to the logout view of this app. It
            should be pre-registered in AWS Cognito
          login_after: whether to show the login screen after logout (unsupported
            for WSO2)

        Returns:
          HttpResponseRedirect to WSO2 logout endpoint
        """
        server_metadata = self.load_server_metadata()
        auth_url = list(urlparse(server_metadata["end_session_endpoint"]))
        auth_url[4] = urlencode(
            {"client_id": self.client_id, "post_logout_redirect_uri": redirect_uri}
        )
        logout_url = urlunparse(auth_url)
        return HttpResponseRedirect(logout_url)

    @staticmethod
    def extract_provider_name(claims):
        """Return provider name from claim and `None` if not found"""
        return None

    @staticmethod
    def extract_username(claims) -> str:
        """Return username from claims"""
        return claims["email"]

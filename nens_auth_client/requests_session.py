from .models import RemoteUser
from .oauth import get_oauth_client
from requests import Session
from typing import Optional, List, Union
from django.conf import settings


def refresh_token(remote_user: RemoteUser):
    client = get_oauth_client()
    tokens = client.fetch_access_token(
        refresh_token=remote_user.refresh_token, grant_type="refresh_token"
    )
    remote_user.id_token = tokens["id_token"]
    remote_user.access_token = tokens["access_token"]
    remote_user.save()


class OAuth2Session(Session):
    """A requests.Session for accessing a Resource Server on behalf of a user.

    This is intended for the Client in the OAuth2 Authorization Code Grant.

    Automatically refreshes if the access token is expired; in that case,
    the RemoteUser will be updated with a new id_token and access_token.

    Args:
        remote_user: the RemoteUser to get/set the tokens
        **kwargs: see requests.Session.

    Raises:
        - ``authlib.integrations.base_client.errors.OAuthError``: OAuth2 errors.
            These are defined in https://tools.ietf.org/html/rfc6749#section-4.1.2.1.
            The error descriptions can be shown to the user.
    """

    def __init__(self, remote_user: RemoteUser, **kwargs):
        super().__init__(**kwargs)

        self.headers.update({"Authorization": f"Bearer {remote_user.access_token}"})

        def update_token_on_request(r, *args, **kwargs):
            if r.status_code == 401 and not getattr(r.request, "refresh_done", False):
                # Refresh the token
                refresh_token(remote_user=remote_user)
                self.headers.update(
                    {"Authorization": f"Bearer {remote_user.access_token}"}
                )

                # Resend the request
                r.request.refresh_done = True  # prevent infinite recursion
                r.request.headers["Authorization"] = self.headers["Authorization"]
                return self.send(r.request, verify=False)

        self.hooks["response"].append(update_token_on_request)


def fetch_cc_token(scope: str, force: bool = False):
    client = get_oauth_client()
    if not hasattr(client, "cc_token_cache"):
        client.cc_token_cache = {}

    if force or (scope not in client.cc_token_cache):
        # Fetch the token
        tokens = client.fetch_access_token(grant_type="client_credentials", scope=scope)
        client.cc_token_cache[scope] = tokens["access_token"]

    return client.cc_token_cache[scope]


class OAuth2CCSession(Session):
    """A requests.Session for accessing a Resource Server for machine-to-machine
    communication.

    This is intended for the Client in the OAuth2 Client Credentials Grant.

    The token is cached (for each scope separately) on the global oauth2 client
    object. It is refreshed automatically if the access token is expired.

    Args:
        scope: a list of scopes for the token. Defaults to settings.NENS_AUTH_SCOPE.
        **kwargs: see requests.Session.

    Raises:
        - ``authlib.integrations.base_client.errors.OAuthError``: OAuth2 errors.
            These are defined in https://tools.ietf.org/html/rfc6749#section-4.1.2.1.
            The error descriptions can be shown to the user.
    """

    def __init__(self, scope: Optional[Union[str, List[str]]] = None, **kwargs):
        super().__init__(**kwargs)

        if scope is None:
            scope = settings.NENS_AUTH_SCOPE

        # Convert list to str
        if not isinstance(scope, str):
            scope = " ".join(scope)

        token = fetch_cc_token(scope=scope)
        self.headers.update({"Authorization": f"Bearer {token}"})

        def update_token_on_request(r, *args, **kwargs):
            if r.status_code == 401 and not getattr(r.request, "refresh_done", False):
                # Refresh the token
                token = fetch_cc_token(scope=scope, force=True)
                self.headers.update({"Authorization": f"Bearer {token}"})

                # Resend the request
                r.request.refresh_done = True  # prevent infinite recursion
                r.request.headers["Authorization"] = self.headers["Authorization"]
                return self.send(r.request, verify=False)

        self.hooks["response"].append(update_token_on_request)

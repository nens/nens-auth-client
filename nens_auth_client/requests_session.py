from .models import RemoteUser
from .oauth import get_oauth_client
from requests import Session


def refresh_token(remote_user: RemoteUser):
    client = get_oauth_client()
    tokens = client.fetch_access_token(
        refresh_token=remote_user.refresh_token, grant_type="refresh_token"
    )
    remote_user.id_token = tokens["id_token"]
    remote_user.access_token = tokens["access_token"]
    remote_user.save()


class OAuth2Session(Session):
    """A requests.Session constructed from a RemoteUser

    Automatically refreshes if the access token is out of date; in that case,
    the RemoteUser will be updated with a new access_token and refresh_token.

    Args:
        remote_user: the RemoteUser to get/set the tokens
        valid_seconds: if the access_token is valid less than this many seconds then
            the token will be refreshed
        **kwargs: see to authlib.integrations.requests_client.OAuth2Session and
            then to requests.Session.
    """

    def __init__(self, remote_user: RemoteUser, **kwargs):
        def update_token_on_request(r, *args, **kwargs):
            if r.status_code == 401 and not getattr(r.request, "refresh_done", False):
                # Refresh the token
                refresh_token(remote_user)
                self.headers.update(
                    {"Authorization": f"Bearer {remote_user.access_token}"}
                )

                # Resend the request
                r.request.refresh_done = True  # prevent infinite recursion
                r.request.headers["Authorization"] = self.headers["Authorization"]
                return self.send(r.request, verify=False)

        super().__init__(**kwargs)

        self.headers.update({"Authorization": f"Bearer {remote_user.access_token}"})
        self.hooks["response"].append(update_token_on_request)

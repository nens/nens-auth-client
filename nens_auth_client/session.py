from authlib.integrations.requests_client import OAuth2Session
from .models import RemoteUser
from .oauth import get_oauth_client
from .jwt_utils import decode_jwt
import time


def get_session_for(remote_user: RemoteUser, valid_seconds=60):
    """Return a requests.Session enriched with a OAuth2 access token configured.

    Automatically refreshes if the access token is out of date; in that case, the RemoteUser
    will be updated with a new access_token and refresh_token.

    Args:
        remote_user: the RemoteUser to get the tokens from
        valid_secons: if the access_token is valid less than this many seconds, then
            the token will be refreshed.

    Returns:
        requests.Session subclass (authlib.integrations.requests_client.OAuth2Session)
    """
    client = get_oauth_client()

    session = OAuth2Session(
        client.client_id,
        client.client_secret,
        token={
            "access_token": remote_user.access_token,
            "refresh_token": remote_user.refresh_token,
            "expires_at": decode_jwt(remote_user.access_token)["exp"],
        },
    )

    # Note: Authlib / requests doesn't expose a means to refresh a token when
    # necessary. We do it here with a
    if (session.token.expires_at - valid_seconds) < int(time.time()):
        session.refresh_token(client.load_server_metadata()["token_endpoint"])
        remote_user.id_token = session.token.id_token
        remote_user.access_token = session.token.access_token
        remote_user.refresh_token = session.token.refresh_token
        remote_user.save()

    return session

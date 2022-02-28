from nens_auth_client.models import RemoteUser
from nens_auth_client.requests_session import OAuth2Session
from urllib.parse import parse_qs
import pytest


@pytest.fixture
def remote_user(access_token_generator):
    return RemoteUser(
        access_token=access_token_generator(),
        refresh_token="foo",
    )


def test_no_refresh(rq_mocker, remote_user):
    session = OAuth2Session(remote_user)

    rq_mocker.get("http://api.foo.bar", json={"data": "Hello World!"}, status_code=200)
    response = session.get("http://api.foo.bar")
    assert response.json() == {"data": "Hello World!"}


def test_refresh(rq_mocker, openid_configuration, remote_user):
    valid_token = remote_user.access_token
    remote_user.access_token = "Invalid"

    session = OAuth2Session(remote_user)

    rq_mocker.get(
        "http://api.foo.bar/",
        status_code=401
    )
    rq_mocker.post(
        openid_configuration["token_endpoint"], json={"id_token": "foo", "access_token": valid_token, "refresh_token": "bar"}
    )

    session.get("http://api.foo.bar/")
    
    # expect 4 requests:
    a, b, c, d = rq_mocker.request_history
    # Initial request
    assert rq_mocker.request_history[0].url == "http://api.foo.bar/"

    # Auth server auto discovery (tested elsewere)
    assert "openid-configuration" in rq_mocker.request_history[1].url

    # Refresh token
    assert rq_mocker.request_history[2].url == openid_configuration["token_endpoint"]
    qs = parse_qs(rq_mocker.request_history[2].text)
    assert qs["grant_type"] == ["refresh_token"]
    assert qs["refresh_token"] == [remote_user.refresh_token]

    # Request with refreshed token
    assert rq_mocker.request_history[3].url == "http://api.foo.bar/"

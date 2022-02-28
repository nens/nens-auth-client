from nens_auth_client.models import RemoteUser
from nens_auth_client.requests_session import OAuth2Session
from unittest import mock
from urllib.parse import parse_qs

import pytest


@pytest.fixture
def remote_user(access_token_generator):
    remote_user = RemoteUser(
        access_token=access_token_generator(),
        refresh_token="foo",
    )
    with mock.patch.object(remote_user, "save"):
        yield remote_user


def test_no_refresh(rq_mocker, remote_user):
    session = OAuth2Session(remote_user)

    # Mock an API
    rq_mocker.get("http://api.foo.bar", json={"data": "Hello World!"}, status_code=200)

    response = session.get("http://api.foo.bar")
    assert response.json() == {"data": "Hello World!"}

    # Expect 1 request in the request history
    request_list = rq_mocker.request_history
    assert len(request_list) == 1
    assert (
        request_list[0].headers["Authorization"] == f"Bearer {remote_user.access_token}"
    )


def test_refresh(rq_mocker, openid_configuration, remote_user):
    valid_token = remote_user.access_token
    remote_user.access_token = "some-invalid-token"

    session = OAuth2Session(remote_user)

    rq_mocker.get("http://api.foo.bar/", status_code=401)
    rq_mocker.post(
        openid_configuration["token_endpoint"],
        json={"id_token": "foo", "access_token": valid_token, "refresh_token": "bar"},
    )

    session.get("http://api.foo.bar/")

    # Expect 4 requests in the request history
    request_list = rq_mocker.request_history
    assert len(request_list) == 4

    # Initial request
    assert request_list[0].url == "http://api.foo.bar/"

    # Auth server auto discovery (tested elsewere)
    assert "openid-configuration" in request_list[1].url

    # Refresh token fetch
    assert request_list[2].url == openid_configuration["token_endpoint"]
    qs = parse_qs(request_list[2].text)
    assert qs["grant_type"] == ["refresh_token"]
    assert qs["refresh_token"] == [remote_user.refresh_token]

    # Request with refreshed token
    assert request_list[3].url == "http://api.foo.bar/"
    assert request_list[3].headers["Authorization"] == f"Bearer {valid_token}"

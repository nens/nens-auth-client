from nens_auth_client.models import RemoteUser
from nens_auth_client.oauth import get_oauth_client
from nens_auth_client.requests_session import OAuth2Session, OAuth2CCSession
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

    request_list = rq_mocker.request_history

    # Initial request
    assert request_list[0].url == "http://api.foo.bar/"

    # Pick the token request (from the JWKS and OpenID Discovery requests)
    token_request = next(
        request
        for request in request_list
        if request.url == openid_configuration["token_endpoint"]
    )
    qs = parse_qs(token_request.text)
    assert qs["grant_type"] == ["refresh_token"]
    assert qs["refresh_token"] == [remote_user.refresh_token]

    # Request with refreshed token
    assert request_list[-1].url == "http://api.foo.bar/"
    assert request_list[-1].headers["Authorization"] == f"Bearer {valid_token}"


def test_client_credentials_cached(rq_mocker, openid_configuration):
    client = get_oauth_client()
    client.cc_token_cache = {"scope1": "cached-token"}

    session = OAuth2CCSession(scope=["scope1"])

    # Mock an API
    rq_mocker.get("http://api.foo.bar", json={"data": "Hello World!"}, status_code=200)

    response = session.get("http://api.foo.bar")
    assert response.json() == {"data": "Hello World!"}

    # Expect 1 request in the request history
    request_list = rq_mocker.request_history
    assert len(request_list) == 1
    assert request_list[0].headers["Authorization"] == "Bearer cached-token"


def test_client_credentials_no_cache(rq_mocker, openid_configuration):
    client = get_oauth_client()
    if hasattr(client, "cc_token_cache"):
        del client.cc_token_cache

    # Mock an API
    rq_mocker.get("http://api.foo.bar", json={"data": "Hello World!"}, status_code=200)

    # Mock the Cognito token endpoint
    rq_mocker.post(
        openid_configuration["token_endpoint"],
        json={"access_token": "fetched-token"},
    )

    session = OAuth2CCSession(scope=["scope1"])
    session.get("http://api.foo.bar/")

    request_list = rq_mocker.request_history

    # Pick the token request (from the JWKS and OpenID Discovery requests)
    token_request = next(
        request
        for request in request_list
        if request.url == openid_configuration["token_endpoint"]
    )
    qs = parse_qs(token_request.text)
    assert qs["grant_type"] == ["client_credentials"]
    assert qs["scope"] == ["scope1"]

    # Request with token
    assert request_list[-1].url == "http://api.foo.bar/"
    assert request_list[-1].headers["Authorization"] == "Bearer fetched-token"


def test_client_credentials_refresh(rq_mocker, openid_configuration):
    client = get_oauth_client()
    client.cc_token_cache = {"scope1": "expired-token"}

    # Mock an API (returns 401 so that refresh is triggered)
    rq_mocker.get("http://api.foo.bar", status_code=401)

    # Mock the Cognito token endpoint
    rq_mocker.post(
        openid_configuration["token_endpoint"],
        json={"access_token": "fetched-token"},
    )

    session = OAuth2CCSession(scope="scope1")
    session.get("http://api.foo.bar/")

    request_list = rq_mocker.request_history

    # Initial request
    assert request_list[0].url == "http://api.foo.bar/"

    # Pick the token request (from the JWKS and OpenID Discovery requests)
    token_request = next(
        request
        for request in request_list
        if request.url == openid_configuration["token_endpoint"]
    )
    qs = parse_qs(token_request.text)
    assert qs["grant_type"] == ["client_credentials"]
    assert qs["scope"] == ["scope1"]

    # Request with token
    assert request_list[-1].url == "http://api.foo.bar/"
    assert request_list[-1].headers["Authorization"] == "Bearer fetched-token"

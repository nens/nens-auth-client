from django.contrib.auth import get_user_model
from nens_auth_client.rest_framework import OAuth2TokenAuthentication
from rest_framework.test import APIRequestFactory

import pytest

UserModel = get_user_model()


@pytest.fixture
def r():
    return APIRequestFactory().get("/")


@pytest.fixture
def mocked_oauth_client(mocker):
    get_oauth_client = mocker.patch(
        "nens_auth_client.rest_framework.authentication.get_oauth_client"
    )
    get_oauth_client.return_value.parse_access_token.return_value = {"scope": "foo"}
    return get_oauth_client.return_value


@pytest.fixture
def mocked_authenticate(mocker):
    authenticate = mocker.patch("django.contrib.auth.authenticate")
    authenticate.return_value = UserModel(username="testuser")
    return authenticate


@pytest.fixture
def authenticator():
    return OAuth2TokenAuthentication()


def test_authentication_class(
    r, authenticator, access_token_generator, mocked_oauth_client, mocked_authenticate
):
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + access_token_generator()
    user, auth = authenticator.authenticate(r)
    assert user.username == "testuser"
    assert auth.scope == "foo"


def test_authentication_class_no_header(r, authenticator):
    assert authenticator.authenticate(r) is None


def test_authentication_class_no_bearer(r, authenticator, access_token_generator):
    r.META["HTTP_AUTHORIZATION"] = "Token xxx"
    assert authenticator.authenticate(r) is None

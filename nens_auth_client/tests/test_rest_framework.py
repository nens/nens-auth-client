import pytest

from nens_auth_client.rest_framework import OAuth2TokenAuthentication
from rest_framework.test import APIRequestFactory

from django.contrib.auth import get_user_model

UserModel = get_user_model()


@pytest.fixture
def r():
    return APIRequestFactory().get("/")


@pytest.fixture
def mocked_authenticator(rf, mocker, rq_mocker, jwks_request, settings):
    """Mock necessary functions to test AccessTokenMiddleware request"""
    # Mock the user association call
    authenticate = mocker.patch("django.contrib.auth.authenticate")
    authenticate.return_value = UserModel(username="testuser")
    # Disable the custom AWS Cognito Access Token mapping
    mocker.patch("nens_auth_client.cognito.preprocess_access_token")
    # Make a middleware that returns the request as a response
    return OAuth2TokenAuthentication()


def test_authentication_class(r, mocked_authenticator, access_token_generator):
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + access_token_generator()
    user, auth = mocked_authenticator.authenticate(r)
    assert user.username == "testuser"
    assert auth.scope == "readwrite"


def test_authentication_class_no_header(r, mocked_authenticator):
    assert mocked_authenticator.authenticate(r) is None


def test_authentication_class_no_bearer(r, mocked_authenticator, access_token_generator):
    r.META["HTTP_AUTHORIZATION"] = "Token xxx"
    assert mocked_authenticator.authenticate(r) is None


def test_authentication_header(r, mocked_authenticator):
    assert mocked_authenticator.authenticate_header(r) == "Bearer"

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from nens_auth_client.middleware import AccessTokenMiddleware

import pytest


UserModel = get_user_model()


@pytest.fixture
def middleware_mocker(mocker, rq_mocker, jwks, settings):
    """Mock necessary functions and create an authorization request"""
    # Mock the call to the external jwks
    rq_mocker.get(settings.NENS_AUTH_JWKS_URI, json=jwks)
    # Mock the user association call
    authenticate = mocker.patch("django.contrib.auth.authenticate")
    authenticate.return_value = UserModel(username="testuser")
    # Disable automatic RemoteUser creation
    settings.NENS_AUTH_AUTO_CREATE_REMOTE_USER = False
    return {"authenticate": authenticate}


def test_oauth2_middleware(rf, access_token_generator, middleware_mocker, settings):
    token = access_token_generator(sub="abcd")
    request = rf.get("/", HTTP_AUTHORIZATION="Bearer " + token)
    request.user = AnonymousUser()

    processed = AccessTokenMiddleware(lambda x: x)(request)
    assert processed.user.username == "testuser"

    assert middleware_mocker["authenticate"].called
    claims = middleware_mocker["authenticate"].call_args[1]["claims"]
    assert claims["sub"] == "abcd"

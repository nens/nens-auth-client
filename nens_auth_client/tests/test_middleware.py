from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from nens_auth_client.middleware import AccessTokenMiddleware

import time
import pytest


UserModel = get_user_model()


@pytest.fixture
def mocked_middleware(rf, mocker, rq_mocker, jwks, settings):
    """Mock necessary functions to test AccessTokenMiddleware request"""
    # Mock the call to the external jwks
    rq_mocker.get(settings.NENS_AUTH_JWKS_URI, json=jwks)
    # Mock the user association call
    authenticate = mocker.patch("django.contrib.auth.authenticate")
    authenticate.return_value = UserModel(username="testuser")
    # Disable automatic RemoteUser creation
    settings.NENS_AUTH_AUTO_CREATE_REMOTE_USER = False
    # Disable the custom AWS Cognito Access Token mapping
    settings.NENS_AUTH_PREPROCESS_ACCESS_TOKEN = None
    # Make a middleware that returns the request as a response
    middleware = AccessTokenMiddleware(get_response=lambda x: x)
    return middleware


@pytest.fixture
def r(rf):
    # Mock a request with an anonymous user
    request = rf.get("/")
    request.user = AnonymousUser()
    return request


def test_middleware(r, access_token_generator, mocked_middleware):
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + access_token_generator()
    processed_request = mocked_middleware(r)
    assert processed_request.user.username == "testuser"
    assert processed_request.user.oauth2_scope == "readwrite"


def test_middleware_wrong_issuer(r, access_token_generator, mocked_middleware):
    token = access_token_generator(iss="https://google.com")
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + token
    processed_request = mocked_middleware(r)
    assert processed_request.user.is_anonymous


def test_middleware_wrong_aud(r, access_token_generator, mocked_middleware):
    token = access_token_generator(aud="https://my/api/")
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + token
    processed_request = mocked_middleware(r)
    assert processed_request.user.is_anonymous


def test_middleware_expired(r, access_token_generator, mocked_middleware):
    # Note that authlib has a 120 seconds "leeway" (for clock skew)
    token = access_token_generator(exp=int(time.time()) - 121)
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + token
    processed_request = mocked_middleware(r)
    assert processed_request.user.is_anonymous


def test_middleware_corrupt_signature(r, access_token_generator, mocked_middleware):
    token = access_token_generator()
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + token[:-1]
    processed_request = mocked_middleware(r)
    assert processed_request.user.is_anonymous


def test_middleware_bad_signature(r, access_token_generator, mocked_middleware):
    token = access_token_generator()
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + token[:-16]
    processed_request = mocked_middleware(r)
    assert processed_request.user.is_anonymous


def test_middleware_unsigned_token(r, access_token_generator, mocked_middleware):
    token = access_token_generator(alg="none")
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + token
    processed_request = mocked_middleware(r)
    assert processed_request.user.is_anonymous


def test_middleware_invalid_key_id(r, access_token_generator, mocked_middleware):
    token = access_token_generator(kid="unknown_key_id")
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + token
    # Current implementation raises ValueError. An internal server error in
    # this case may be justified?
    with pytest.raises(ValueError):
        mocked_middleware(r)

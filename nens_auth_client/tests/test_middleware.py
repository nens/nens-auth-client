import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser

from nens_auth_client.middleware import AccessTokenMiddleware

UserModel = get_user_model()


@pytest.fixture
def mocked_middleware(rf, mocker, rq_mocker, jwks_request, settings):
    """Mock necessary functions to test AccessTokenMiddleware request"""
    # Mock the user association call
    authenticate = mocker.patch("django.contrib.auth.authenticate")
    authenticate.return_value = UserModel(username="testuser")
    # Disable the custom AWS Cognito Access Token mapping
    mocker.patch("nens_auth_client.cognito.preprocess_access_token")
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


def test_middleware_logged_in_user(r, access_token_generator, mocked_middleware):
    # An already logged in user (e.g. session cookie) is unchanged
    r.user = UserModel(username="otheruser")
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + access_token_generator()
    processed_request = mocked_middleware(r)
    assert processed_request.user.username == "otheruser"

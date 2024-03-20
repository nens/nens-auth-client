from authlib.jose.errors import JoseError
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from nens_auth_client.middleware import AccessTokenMiddleware

import pytest

UserModel = get_user_model()


@pytest.fixture
def mocked_oauth_client(mocker):
    get_oauth_client = mocker.patch("nens_auth_client.middleware.get_oauth_client")
    get_oauth_client.return_value.parse_access_token.return_value = {"scope": "foo"}
    return get_oauth_client.return_value


@pytest.fixture
def mocked_authenticate(mocker):
    authenticate = mocker.patch("django.contrib.auth.authenticate")
    authenticate.return_value = UserModel(username="testuser")
    return authenticate


@pytest.fixture
def middleware():
    return AccessTokenMiddleware(get_response=lambda x: x)


@pytest.fixture
def r(rf):
    # Mock a request with an anonymous user
    request = rf.get("/")
    request.user = AnonymousUser()
    return request


def test_middleware(
    r, access_token_generator, mocked_oauth_client, mocked_authenticate, middleware
):
    token = access_token_generator()
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + token

    processed_request = middleware(r)
    assert processed_request.user.username == "testuser"
    assert processed_request.user.oauth2_scope == "foo"

    mocked_oauth_client.parse_access_token.assert_called_once_with(
        token, leeway=settings.NENS_AUTH_LEEWAY
    )
    mocked_authenticate.assert_called_once_with(
        r, claims=mocked_oauth_client.parse_access_token.return_value
    )


def test_middleware_logged_in_user(
    r, access_token_generator, middleware, mocked_oauth_client
):
    # An already logged in user (e.g. session cookie) is unchanged
    r.user = UserModel(username="otheruser")
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + access_token_generator()
    processed_request = middleware(r)
    assert processed_request.user.username == "otheruser"

    assert not mocked_oauth_client.parse_access_token.called


def test_middleware_no_token(r, middleware, mocked_oauth_client):
    middleware(r)

    assert not mocked_oauth_client.parse_access_token.called


def test_middleware_invalid_token(
    r, access_token_generator, mocked_oauth_client, mocked_authenticate, middleware
):
    token = access_token_generator()
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + token

    mocked_oauth_client.parse_access_token.side_effect = JoseError()

    processed_request = middleware(r)
    assert not processed_request.user.is_authenticated

    mocked_oauth_client.parse_access_token.assert_called_once_with(
        token, leeway=settings.NENS_AUTH_LEEWAY
    )
    assert not mocked_authenticate.called


def test_middleware_no_authentication(
    r, access_token_generator, mocked_oauth_client, mocked_authenticate, middleware
):
    mocked_authenticate.return_value = None

    token = access_token_generator()
    r.META["HTTP_AUTHORIZATION"] = "Bearer " + token

    processed_request = middleware(r)
    assert not processed_request.user.is_authenticated

    mocked_oauth_client.parse_access_token.assert_called_once_with(
        token, leeway=settings.NENS_AUTH_LEEWAY
    )
    mocked_authenticate.assert_called_once_with(
        r, claims=mocked_oauth_client.parse_access_token.return_value
    )

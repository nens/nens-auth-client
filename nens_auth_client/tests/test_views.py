import pytest
from contextlib import contextmanager
from urllib.parse import urlparse, urlencode, parse_qs
from nens_auth_client import views
import random
import string
from authlib.jose import jwt
import time

from django.conf import settings



def test_login(rf):
    request = rf.get("/login")
    request.session = {}
    response = views.login(request)

    # login generated a redirect to the AUTHORIZE_URL
    assert response.status_code == 302
    url = urlparse(response.url)
    assert f"{url.scheme}://{url.hostname}{url.path}" == settings.NENS_AUTH_AUTHORIZE_URL

    # The query params are conform OpenID Connect spec
    # https://tools.ietf.org/html/rfc6749#section-4.1.1
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    qs = parse_qs(url.query)
    assert qs["response_type"] == ["code"]
    assert qs["client_id"] == [settings.NENS_AUTH_CLIENT_ID]
    assert qs["redirect_uri"] == [settings.NENS_AUTH_REDIRECT_URI]
    assert qs["scope"] == [settings.NENS_AUTH_SCOPE]
    assert qs["state"] == [request.session["_cognito_authlib_state_"]]
    assert qs["nonce"] == [request.session["_cognito_authlib_nonce_"]]
    assert request.session["_cognito_authlib_redirect_uri_"] == settings.NENS_AUTH_REDIRECT_URI


@pytest.fixture
def mock_and_authorize(rf, mocker, rq_mocker, jwks):
    """Mock necessary functions and call the authorize view"""

    def func(id_token, code="code", state="state", nonce="nonce"):
        # Mock the call to the external token API
        rq_mocker.post(
            settings.NENS_AUTH_ACCESS_TOKEN_URL,
            json={"id_token": id_token}
        )
        # Mock the call to the external jwks
        rq_mocker.get(
            settings.NENS_AUTH_JWKS_URI,
            json=jwks
        )
        # Mock the user association logic (it needs db access)
        associate_user = mocker.patch("nens_auth_client.views.associate_user")
        associate_user.return_value = None

        # Create the request
        request = rf.get(f"/authorize?code={code}&state={state}")
        request.session = {
            "_cognito_authlib_state_": state,
            "_cognito_authlib_nonce_": nonce,
        }
        return views.authorize(request)

    return func


def test_authorize(id_token_generator, mock_and_authorize, rq_mocker):
    id_token = id_token_generator()
    response = mock_and_authorize(id_token)
    assert response.status_code == 200  # all checks passed

    token_request, jwks_request = rq_mocker.request_history
    assert token_request.url == settings.NENS_AUTH_ACCESS_TOKEN_URL
    qs = parse_qs(token_request.text)
    assert qs["grant_type"] == ["authorization_code"]
    assert qs["code"] == ["code"]
    assert qs["state"] == ["state"]
    assert jwks_request.url == settings.NENS_AUTH_JWKS_URI

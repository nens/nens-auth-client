import pytest
from urllib.parse import urlparse, urlencode, parse_qs
from nens_auth_client import views
from django.http import HttpResponseRedirect
import random
import requests_mock
from authlib.jose import jwt

from django.conf import settings


def test_login(rf):
    request = rf.get("/login")
    request.session = {}
    response = views.login(request)

    # login generated a redirect to the AUTHORIZE_URL
    assert response.status_code == HttpResponseRedirect.status_code
    url = urlparse(response.url)
    assert url.hostname + url.path == settings.NENS_AUTH_AUTHORIZE_URL

    # The query params are conform OpenID Connect spec
    # https://tools.ietf.org/html/rfc6749#section-4.1.1
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    qs = parse_qs(url.query)
    assert qs["response_type"] == ["code"]
    assert qs["client_id"] == [settings.NENS_AUTH_CLIENT_ID]
    assert qs["redirect_uri"] == [settings.NENS_AUTH_REDIRECT_URI]
    assert qs["scope"] == [settings.NENS_AUTH_SCOPE]
    assert qs["state"] == request.session["_cognito_authlib_state_"]
    assert qs["nonce"] == request.session["_cognito_authlib_nonce_"]
    assert request.session["_cognito_authlib_state_"] == settings.NENS_AUTH_REDIRECT_URI


@requests_mock.Mocker(kw="mocker")
def test_authorize(rf, mocker, id_token, jwks):
    mocker.post(
        settings.NENS_AUTH_ACCESS_TOKEN_URL,
        json={"id_token": id_token}
    )
    mocker.get(
        settings.NENS_AUTH_JWKS_URI,
        json=jwks
    )
    request = rf.get("/authorize?code=abcd&state=efgh")
    request.session = {"_cognito_authlib_state_": "efgh"}
    response = views.authorize(request)

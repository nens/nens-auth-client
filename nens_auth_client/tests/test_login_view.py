import pytest
from urllib.parse import urlparse, parse_qs
from nens_auth_client import views
from django.conf import settings
from django.contrib.auth.models import AnonymousUser, User


def test_login(rf, openid_configuration):
    request = rf.get("http://testserver/login/?next=/a")
    request.session = {}
    request.user = AnonymousUser()  # user is not logged in initially!
    response = views.login(request)

    # login generated a redirect to the AUTHORIZE_URL
    assert response.status_code == 302
    url = urlparse(response.url)
    url_no_qs = url.scheme + "://" + url.hostname + url.path
    assert url_no_qs == openid_configuration["authorization_endpoint"]

    # The query params are conform OpenID Connect spec
    # https://tools.ietf.org/html/rfc6749#section-4.1.1
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    qs = parse_qs(url.query)
    assert qs["response_type"] == ["code"]
    assert qs["client_id"] == [settings.NENS_AUTH_CLIENT_ID]
    assert qs["redirect_uri"] == ["http://testserver/authorize/"]
    assert qs["scope"] == [" ".join(settings.NENS_AUTH_SCOPE)]
    assert qs["state"] == [request.session["_cognito_authlib_state_"]]
    assert qs["nonce"] == [request.session["_cognito_authlib_nonce_"]]
    assert request.session[views.LOGIN_REDIRECT_SESSION_KEY] == "/a"

    # check if Cache-Control header is set to "no-store"
    assert response._headers["cache-control"] == ("Cache-Control", "no-store")


def test_login_when_already_logged_in(rf):
    # The login view redirects to DEFAULT_SUCCESS_URL if already logged in
    request = rf.get("http://testserver/login/?next=/a")
    request.session = {}
    request.user = User()
    response = views.login(request)

    # login generated a redirect to the 'next' parameter
    assert response.status_code == 302
    assert response.url == "/a"

    # login did not add anything to the session
    assert request.session == {}


def test_login_no_next_url(rf):
    # The login view redirects to DEFAULT_SUCCESS_URL if already logged in
    request = rf.get("http://testserver/login/")
    request.session = {}
    request.user = User()
    views.login(request)

    # login did not add a redirect url to the session
    assert views.LOGIN_REDIRECT_SESSION_KEY not in request.session


def test_login_no_next_url_already_logged_in(rf):
    # The login view redirects to DEFAULT_SUCCESS_URL if already logged in
    request = rf.get("http://testserver/login/")
    request.session = {}
    request.user = User()
    response = views.login(request)

    # login generated a redirect to the default redirect setting
    assert response.status_code == 302
    assert response.url == settings.NENS_AUTH_DEFAULT_SUCCESS_URL


@pytest.mark.parametrize(
    "url,expected",
    [
        ("login/", None),
        ("login/?next=/a", "/a"),
        ("login/?next=https://testserver/a", "https://testserver/a"),
        ("login/?next=https://testserver2/a", None),  # different domain
        ("login/?next=http://testserver/a", None),  # https to http
    ],
)
def test_get_redirect_from_next(rf, url, expected):
    request = rf.get(url, secure=True)
    assert views._get_redirect_from_next(request) == expected


@pytest.mark.parametrize("logged_in", [True, False])
def test_login_with_forced_logout(rf, openid_configuration, mocker, logged_in):
    django_logout = mocker.patch("nens_auth_client.views.django_auth.logout")

    request = rf.get("http://testserver/login/?next=/a&logout=true")
    request.session = {}
    request.user = User() if logged_in else AnonymousUser()
    response = views.login(request)

    assert django_logout.called

    # login generated a redirect to the LOGOUT URL
    assert response.status_code == 302
    url = urlparse(response.url)
    assert url[:3] == ("https", "authserver", "/logout")

    # The query params are conform OpenID Connect spec
    # https://tools.ietf.org/html/rfc6749#section-4.1.1
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    qs = parse_qs(url.query)
    assert qs["response_type"] == ["code"]
    assert qs["client_id"] == [settings.NENS_AUTH_CLIENT_ID]
    assert qs["redirect_uri"] == ["http://testserver/authorize/"]
    assert qs["scope"] == [" ".join(settings.NENS_AUTH_SCOPE)]
    assert qs["state"] == [request.session["_cognito_authlib_state_"]]
    assert qs["nonce"] == [request.session["_cognito_authlib_nonce_"]]
    assert request.session[views.LOGIN_REDIRECT_SESSION_KEY] == "/a"

    # check if Cache-Control header is set to "no-store"
    assert response._headers["cache-control"] == ("Cache-Control", "no-store")

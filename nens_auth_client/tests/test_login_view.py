import pytest
from urllib.parse import urlparse, parse_qs
from nens_auth_client import views
from django.conf import settings
from django.contrib.auth.models import AnonymousUser, User


def test_login(rf):
    request = rf.get("http://testserver/login?next=/a")
    request.session = {}
    request.user = AnonymousUser()  # user is not logged in initially!
    response = views.login(request)

    # login generated a redirect to the AUTHORIZE_URL
    assert response.status_code == 302
    url = urlparse(response.url)
    url_no_qs = url.scheme + "://" + url.hostname + url.path
    assert url_no_qs == settings.NENS_AUTH_AUTHORIZE_URL

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
    assert request.session[views.REDIRECT_SESSION_KEY] == "http://testserver/a"


def test_login_when_already_logged_in(rf):
    # The login view redirects to DEFAULT_SUCCESS_URL if already logged in
    request = rf.get("http://testserver/login?next=/a")
    request.session = {}
    request.user = User()
    response = views.login(request)

    # login generated a redirect to the (absolutized) 'next' parameter
    assert response.status_code == 302
    assert response.url == "http://testserver/a"


@pytest.mark.parametrize(
    "url,expected",
    [
        ("/login", "http://testserver/admin"),
        ("/login?next=a", "http://testserver/a"),
        ("/login?next=http://testserver/a", "http://testserver/a"),
        ("/login?next=http://testserver2/a", "http://testserver/admin"),
    ],
)
def test_get_absolute_succes_url(rf, url, expected):
    request = rf.get(url)
    assert views._get_absolute_success_url(request) == expected

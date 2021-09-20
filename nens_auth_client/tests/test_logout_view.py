from urllib.parse import parse_qs
from urllib.parse import urlparse
from nens_auth_client import views
from django.conf import settings
from django.contrib.auth.models import AnonymousUser, User
from django.core.exceptions import PermissionDenied

import pytest
import re


@pytest.mark.parametrize("logged_in", [True, False])
def test_logout(rf, mocker, openid_configuration, logged_in):
    django_logout = mocker.patch("nens_auth_client.views.django_auth.logout")

    request = rf.get("http://testserver/logout/?next=/a")
    request.session = {}
    request.user = User() if logged_in else AnonymousUser()
    response = views.logout(request)

    # login generated a redirect to the LOGOUT_URL
    assert response.status_code == 302
    url = urlparse(response.url)
    assert url[:3] == ("https", "authserver", "/logout")
    qs = parse_qs(url.query)
    assert qs["client_id"] == [settings.NENS_AUTH_CLIENT_ID]
    assert qs["logout_uri"] == ["http://testserver/logout-success/"]

    # django logout was called
    assert django_logout.called

    # the 'next' param was stored in the session
    assert request.session[views.LOGOUT_REDIRECT_SESSION_KEY] == "/a"

    # check Cache-Control headers: page should never be cached
    pattern = "max-age=0, no-cache, no-store, must-revalidate(, private)?$"
    assert re.match(pattern, response["cache-control"]) is not None



def test_logout_no_next_url(rf, mocker, openid_configuration):
    mocker.patch("nens_auth_client.views.django_auth.logout")

    request = rf.get("http://testserver/logout/")
    request.session = {}
    views.logout(request)

    # there is no redirect url stored in the session
    assert views.LOGOUT_REDIRECT_SESSION_KEY not in request.session


def test_logout_success(rf, mocker):
    request = rf.get("http://testserver/logout-success/")
    request.session = {views.LOGOUT_REDIRECT_SESSION_KEY: "/b"}
    request.user = AnonymousUser()  # user is not logged in anymore
    response = views.logout_success(request)

    # logout generated a redirect to the url stored in the session
    assert response.status_code == 302
    assert response.url == "/b"

    # check Cache-Control headers: page should never be cached
    pattern = "max-age=0, no-cache, no-store, must-revalidate(, private)?$"
    assert re.match(pattern, response["cache-control"]) is not None



def test_logout_success_empty_session(rf, mocker, openid_configuration):
    request = rf.get("http://testserver/logout-success/")
    request.session = {}
    request.user = AnonymousUser()  # user is not logged in anymore
    response = views.logout_success(request)

    # logout generated a redirect to the default logout url
    assert response.status_code == 302
    assert response.url == settings.NENS_AUTH_DEFAULT_LOGOUT_URL


def test_logout_success_logged_in(rf, mocker):
    # This should only be possible if the user typed in this URL himself.
    # Give PermissionDenied.
    request = rf.get("http://testserver/logout-success/")
    request.session = {}
    request.user = User()  # user is logged in

    with pytest.raises(PermissionDenied):
        views.logout_success(request)

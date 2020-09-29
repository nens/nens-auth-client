from urllib.parse import urlparse
from nens_auth_client import views
from django.conf import settings
from django.contrib.auth.models import AnonymousUser, User


def test_logout(rf, mocker):
    django_logout = mocker.patch("nens_auth_client.views.django_auth.logout")

    request = rf.get("http://testserver/logout/?next=/a")
    request.session = {}
    request.user = User()  # user is logged in initially
    response = views.logout(request)

    # login generated a redirect to the LOGOUT_URL
    assert response.status_code == 302
    url = urlparse(response.url)
    url_no_qs = url.scheme + "://" + url.hostname + url.path
    assert url_no_qs == settings.NENS_AUTH_LOGOUT_URL

    # django logout was called
    assert django_logout.called

    # the 'next' param was stored in the session
    assert request.session[views.LOGOUT_REDIRECT_SESSION_KEY] == "http://testserver/a"


def test_logout_as_callback(rf, mocker):
    django_logout = mocker.patch("nens_auth_client.views.django_auth.logout")

    request = rf.get("http://testserver/logout/?next=/a")
    request.session = {
        views.LOGOUT_REDIRECT_SESSION_KEY: "http://testserver/b"
    }
    request.user = AnonymousUser()  # user is not logged in anymore
    response = views.logout(request)

    # logout generated a redirect to the url stored in the session
    assert response.status_code == 302
    assert response.url == "http://testserver/b"

    # django logout was not called
    assert not django_logout.called


def test_logout_not_logged_in(rf, mocker):
    # A user logs out without being logged in
    django_logout = mocker.patch("nens_auth_client.views.django_auth.logout")

    request = rf.get("http://testserver/logout/?next=/a")
    request.session = {}
    request.user = AnonymousUser()  # user is not logged in initially
    response = views.logout(request)

    # logout generated a redirect to the 'next' URL
    assert response.status_code == 302
    assert response.url == "http://testserver/a"

    # django logout was not called
    assert not django_logout.called

from django.http import Http404
from nens_auth_client import views
from nens_auth_client.models import Invitation
from unittest import mock
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest


@pytest.fixture
def get_object_or_404(mocker):
    return mocker.patch("nens_auth_client.views.get_object_or_404")


def test_invitation_accept(rf, get_object_or_404):
    request = rf.get("/?next=/success/")
    request.user = mock.Mock()
    request.user.is_authenticated = True
    invitation = get_object_or_404.return_value
    invitation.status = Invitation.PENDING

    response = views.accept_invitation(request, "foo")
    assert response.status_code == 302
    assert response.url == "/success/"

    get_object_or_404.assert_called_with(Invitation, slug="foo")
    invitation.accept.assert_called_with(request.user)


def test_invitation_does_not_exist(rf, get_object_or_404):
    """Not-existing invitations give 404, also for anonymous users"""
    request = rf.get("/?next=/success/")
    get_object_or_404.side_effect = Http404

    with pytest.raises(Http404):
        views.accept_invitation(request, "foo")

    get_object_or_404.assert_called_with(Invitation, slug="foo")


def test_invitation_not_acceptable(rf, get_object_or_404):
    """Non-acceptable invitations give 404, also for anonymous users"""
    request = rf.get("/?next=/success/")
    invitation = get_object_or_404.return_value
    invitation.status = Invitation.ACCEPTED

    response = views.accept_invitation(request, "foo")
    assert response.status_code == 404

    get_object_or_404.assert_called_with(Invitation, slug="foo")
    assert not invitation.accept.called


def test_invitation_not_logged_in(rf, get_object_or_404):
    request = rf.get("/some/url/")
    request.user = mock.Mock()
    request.user.is_authenticated = False
    invitation = get_object_or_404.return_value
    invitation.status = Invitation.PENDING

    response = views.accept_invitation(request, "foo")
    assert response.status_code == 302
    _, _, path, _, query, _ = urlparse(response.url)
    assert path == "/login/"
    query_parsed = parse_qs(query)
    assert query_parsed["invitation"] == ["foo"]
    assert query_parsed["next"] == ["/some/url/"]

    get_object_or_404.assert_called_with(Invitation, slug="foo")

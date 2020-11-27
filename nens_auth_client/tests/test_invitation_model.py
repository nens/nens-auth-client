from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from nens_auth_client.models import Invitation

import json
import pytest


@pytest.fixture
def m_permission_backend(mocker):
    cls = mocker.patch("nens_auth_client.permissions.DjangoPermissionBackend")
    return cls.return_value


@pytest.fixture
def m_send_email(mocker):
    return mocker.patch("nens_auth_client.models.send_mail")


@pytest.fixture
def invitation(mocker):
    invitation = Invitation(permissions=json.dumps({"foo": "bar"}))
    mocker.patch.object(invitation, "save")
    return invitation


@pytest.fixture
def user():
    return User(username="testuser", id=1)


def test_accept_no_user(m_permission_backend, user, invitation):
    invitation.accept(user, extra="something")

    assert invitation.status == Invitation.ACCEPTED
    m_permission_backend.assign.assert_called_with(
        permissions={"foo": "bar"}, user=user, extra="something"
    )


def test_accept_matching_user(m_permission_backend, user, invitation):
    invitation.user = user
    invitation.accept(user, extra="something")

    assert invitation.status == Invitation.ACCEPTED
    m_permission_backend.assign.assert_called_with(
        permissions={"foo": "bar"}, user=user, extra="something"
    )


def test_no_accept_user_mismatch(m_permission_backend, user, invitation):
    invitation.user = User(username="other_user", id=42)

    with pytest.raises(PermissionDenied):
        invitation.accept(user, extra="something")

    assert invitation.status == Invitation.PENDING
    assert not m_permission_backend.assign.called


def test_reject(invitation):
    invitation.reject()
    assert invitation.status == Invitation.REJECTED


def test_revoke(invitation):
    invitation.revoke()
    assert invitation.status == Invitation.REVOKED


def test_get_accept_url(rf, invitation):
    request = rf.get("http://testserver/x/y/z")
    actual = invitation.get_accept_url(request)
    expected = "http://testserver/invitations/{}/accept/".format(invitation.slug)
    assert actual == expected


def test_send_email(rf, invitation, m_send_email, settings):
    request = rf.get("http://testserver/x/y/z")
    settings.NENS_AUTH_INVITATION_EMAIL_SUBJECT = "Test Subject"
    invitation.send_email(
        "testuser@test.com", request, send_email_options={"foo": "bar"}
    )

    url = invitation.get_accept_url(request)
    send_email_kwargs = m_send_email.call_args[1]
    assert send_email_kwargs["subject"] == "Test Subject"
    assert url in send_email_kwargs["message"]
    assert '<a href="{}">'.format(url) in send_email_kwargs["html_message"]
    assert send_email_kwargs["recipient_list"] == ["testuser@test.com"]
    assert send_email_kwargs["foo"] == "bar"

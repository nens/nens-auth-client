from django.contrib.auth.models import User
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError
from nens_auth_client import backends

import pytest


@pytest.fixture
def user_getter(mocker):
    UserModel = mocker.patch("nens_auth_client.backends.UserModel")
    return UserModel.objects.get


@pytest.fixture
def remoteuser_create(mocker):
    RemoteUser = mocker.patch("nens_auth_client.backends.RemoteUser")
    return RemoteUser.objects.create


def test_remoteuser_exists(user_getter):
    user_getter.return_value = User(username="testuser")

    user = backends.RemoteUserBackend().authenticate(
        request=None, userinfo={"sub": "remote-uid"}
    )
    assert user.username == "testuser"
    user_getter.assert_called_with(remote__external_user_id="remote-uid")


def test_remoteuser_not_exists(user_getter):
    user_getter.side_effect = ObjectDoesNotExist

    user = backends.RemoteUserBackend().authenticate(
        request=None, userinfo={"sub": "remote-uid"}
    )
    assert user is None
    user_getter.assert_called_with(remote__external_user_id="remote-uid")


def test_emailverified_exists(user_getter):
    user_getter.return_value = User(username="testuser")

    user = backends.EmailVerifiedBackend().authenticate(
        request=None,
        userinfo={
            "sub": "remote-uid",
            "email": "a@b.com",
            "email_verified": True,
        },
    )
    assert user.username == "testuser"
    user_getter.assert_called_with(email__iexact="a@b.com")


def test_emailverified_not_exists(user_getter):
    user_getter.side_effect = ObjectDoesNotExist

    user = backends.EmailVerifiedBackend().authenticate(
        request=None,
        userinfo={
            "sub": "remote-uid",
            "email": "a@b.com",
            "email_verified": True,
        },
    )
    assert user is None
    user_getter.assert_called_with(email__iexact="a@b.com")


def test_emailverified_multiple_exist(user_getter):
    user_getter.side_effect = MultipleObjectsReturned

    user = backends.EmailVerifiedBackend().authenticate(
        request=None,
        userinfo={
            "sub": "remote-uid",
            "email": "a@b.com",
            "email_verified": True,
        },
    )

    assert user is None
    user_getter.assert_called_with(email__iexact="a@b.com")


@pytest.mark.parametrize(
    "userinfo",
    [
        {"sub": "remote-uid", "email": "a@b.com", "email_verified": False},
        {"sub": "remote-uid", "email": "a@b.com"},
        {"sub": "remote-uid", "email": "", "email_verified": True},
        {"sub": "remote-uid", "email_verified": True},
    ],
)
def test_emailverified_no_verified_email(user_getter, userinfo):
    user = backends.EmailVerifiedBackend().authenticate(
        request=None, userinfo=userinfo
    )
    assert user is None
    assert not user_getter.called


def test_create_remoteuser(remoteuser_create):
    user = User(id=42, username="testuser")
    user.backend = None
    backends.create_remoteuser(user, {"sub": "abc"})
    remoteuser_create.assert_called_with(user=user, external_user_id="abc")


def test_create_remoteuser_skip(remoteuser_create):
    user = User(id=42, username="testuser")
    user.backend = backends.REMOTEUSERBACKEND_PATH
    backends.create_remoteuser(user, {"sub": "abc"})
    assert not remoteuser_create.called


def test_create_remoteuser_race_condition(remoteuser_create):
    user = User(id=42, username="testuser")
    user.backend = None
    remoteuser_create.side_effect = IntegrityError

    # ignores the IntegrityError:
    backends.create_remoteuser(user, {"sub": "abc"})
    assert remoteuser_create.called

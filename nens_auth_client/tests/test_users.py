from django.contrib.auth.models import User
from django.db import IntegrityError
from nens_auth_client.users import create_remote_user
from nens_auth_client.users import create_user
from nens_auth_client.users import update_remote_user
from nens_auth_client.users import update_user
from unittest import mock

import pytest
import datetime


@pytest.fixture
def user_mgr(mocker):
    return mocker.patch("nens_auth_client.users.User.objects")


@pytest.fixture
def remoteuser_mgr(mocker):
    return mocker.patch("nens_auth_client.users.RemoteUser.objects")


@pytest.fixture
def atomic_m(mocker):
    return mocker.patch("nens_auth_client.users.transaction.atomic")


def test_create_remoteuser(remoteuser_mgr):
    user = User(id=42, username="testuser")
    create_remote_user(user, {"sub": "abc"})

    remoteuser_mgr.create.assert_called_with(user=user, external_user_id="abc")


def test_create_remoteuser_ignore_if_exists(remoteuser_mgr):
    user = User(id=42, username="testuser")
    remoteuser_mgr.create.side_effect = IntegrityError
    # ignores the IntegrityError:
    create_remote_user(user, {"sub": "abc"})

    remoteuser_mgr.create.assert_called_with(user=user, external_user_id="abc")


def test_create_user(user_mgr, remoteuser_mgr, atomic_m):
    user = User(id=42, username="testuser")
    user_mgr.create_user.return_value = user
    create_user({"sub": "abc", "cognito:username": "testuser"})

    user_mgr.create_user.assert_called_with(username="testuser", password=None)
    remoteuser_mgr.create.assert_called_with(user=user, external_user_id="abc")


def test_update_user(user_mgr, remoteuser_mgr, atomic_m):
    user = mock.Mock()
    user.username = "testuser"
    update_user(
        user,
        {
            "sub": "abc",
            "cognito:username": "somethingdifferent",
            "email": "test@test.com",
            "email_verified": True,
            "given_name": "Lizard",
            "family_name": "People",
        },
    )

    assert user.username == "testuser"
    assert user.email == "test@test.com"
    assert user.first_name == "Lizard"
    assert user.last_name == "People"
    assert user.save.called


def test_update_remote_user(remoteuser_mgr):
    update_remote_user(
        claims={"sub": "test-id"}, tokens={"id_token": "foo", "access_token": "bar"}
    )
    remoteuser_mgr.filter.assert_called_with(external_user_id="test-id")
    args, kwargs = remoteuser_mgr.filter.return_value.update.call_args
    assert kwargs["id_token"] == "foo"
    assert kwargs["access_token"] == "bar"
    assert kwargs["refresh_token"] == ""
    assert isinstance(kwargs["last_modified"], datetime.datetime)

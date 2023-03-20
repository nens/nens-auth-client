from django.contrib.auth.models import User
from django.db import IntegrityError
from nens_auth_client.users import _extract_provider_name
from nens_auth_client.users import create_remote_user
from nens_auth_client.users import create_user
from nens_auth_client.users import update_remote_user
from nens_auth_client.users import update_user
from unittest import mock

import datetime
import pytest


@pytest.fixture
def user_mgr(mocker):
    return mocker.patch("nens_auth_client.users.User.objects")


@pytest.fixture
def remoteuser_mgr(mocker):
    return mocker.patch("nens_auth_client.users.RemoteUser.objects")


@pytest.fixture
def atomic_m(mocker):
    return mocker.patch("nens_auth_client.users.transaction.atomic")


@pytest.fixture
def create_user_m(mocker):
    return mocker.patch("nens_auth_client.users._create_user")


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


def test_create_user_external_idp(user_mgr, remoteuser_mgr, atomic_m):
    # Users coming from external IDPs should get their email as username
    user = User(id=42, username="testuser")
    user_mgr.create_user.return_value = user
    create_user(
        {
            "sub": "abc",
            "cognito:username": "testuser",
            "email": "test@email.com",
            "identities": [{"providerName": "Google"}],
        }
    )

    user_mgr.create_user.assert_called_with(username="test@email.com", password=None)
    remoteuser_mgr.create.assert_called_with(user=user, external_user_id="abc")


def test_create_user_external_idp_no_email(user_mgr, remoteuser_mgr, atomic_m):
    # Users coming from external IDPs without email should be accepted too
    user = User(id=42, username="testuser")
    user_mgr.create_user.return_value = user
    create_user(
        {
            "sub": "abc",
            "cognito:username": "testuser",
            "identities": [{"providerName": "Google"}],
        }
    )

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


def test_update_user_trusted_provider(user_mgr, remoteuser_mgr, atomic_m, settings):
    # Email should be updated for trusted providers even without email_verified.
    user = mock.Mock()
    user.username = "testuser"
    settings.NENS_AUTH_TRUSTED_PROVIDERS = ["Google"]
    update_user(
        user,
        {
            "sub": "abc",
            "cognito:username": "somethingdifferent",
            "email": "test@test.com",
            "email_verified": False,
            "identities": [{"providerName": "Google"}],
            "given_name": "Lizard",
            "family_name": "People",
        },
    )
    assert user.email == "test@test.com"


def test_update_user_no_fields(user_mgr, remoteuser_mgr, atomic_m):
    user = mock.Mock()
    user.username = "testuser"
    update_user(user, {"sub": "abc", "cognito:username": "somethingdifferent"})

    assert user.username == "testuser"
    assert user.email == ""
    assert user.first_name == ""
    assert user.last_name == ""
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


def test_create_user_remoteuser_exists(user_mgr, remoteuser_mgr, atomic_m):
    user_mgr.create_user.side_effect = IntegrityError

    # mock the remote-user existence check
    user_mgr.filter.return_value.exists.return_value = True
    assert create_user({"sub": "abc", "cognito:username": "testuser"}) is None

    assert user_mgr.create_user.call_count == 1
    remoteuser_mgr.filter.assert_called_with(external_user_id="abc")


def test_create_user_username_exists(user_mgr, create_user_m, mocker):
    random_string = mocker.patch("nens_auth_client.users.get_random_string")
    random_string.return_value = "x23f"

    user = User(id=42, username="testuser2")
    create_user_m.side_effect = (IntegrityError, user)

    # mock the user-existence check
    user_mgr.filter.return_value.exists.return_value = True
    assert create_user({"sub": "abc", "cognito:username": "testuser"}) == user

    # _create_user should have been called twice
    assert create_user_m.call_count == 2
    first_call, second_call = create_user_m.call_args_list
    assert first_call[0] == ("testuser", "abc")
    assert second_call[0] == ("testuserx23f", "abc")


def test_extract_provider_name_present():
    # Extract provider name when it is present.
    claims = {"identities": [{"providerName": "Google"}]}
    assert _extract_provider_name(claims) == "Google"


def test_extract_provider_name_absent():
    # Return None when a provider name cannot be found.
    claims = {"some": "claim"}
    assert not _extract_provider_name(claims)

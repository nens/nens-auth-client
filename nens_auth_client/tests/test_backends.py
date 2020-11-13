from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from nens_auth_client import backends

import pytest


@pytest.fixture
def user_getter(mocker):
    UserModel = mocker.patch("nens_auth_client.backends.UserModel")
    return UserModel.objects.get


@pytest.fixture
def create_remoteuser(mocker):
    return mocker.patch("nens_auth_client.backends.create_remoteuser")


def test_remoteuser_exists(user_getter):
    user_getter.return_value = User(username="testuser")

    user = backends.RemoteUserBackend().authenticate(
        request=None, claims={"sub": "remote-uid"}
    )
    assert user.username == "testuser"
    user_getter.assert_called_with(remote__external_user_id="remote-uid")


def test_remoteuser_not_exists(user_getter):
    user_getter.side_effect = ObjectDoesNotExist

    user = backends.RemoteUserBackend().authenticate(
        request=None, claims={"sub": "remote-uid"}
    )
    assert user is None
    user_getter.assert_called_with(remote__external_user_id="remote-uid")


def test_remoteuser_inactive(user_getter):
    user_getter.return_value = User(username="testuser", is_active=False)

    with pytest.raises(PermissionDenied):
        backends.RemoteUserBackend().authenticate(
            request=None, claims={"sub": "remote-uid"}
        )
    user_getter.assert_called_with(remote__external_user_id="remote-uid")


def test_ssomigration_exists(user_getter, create_remoteuser):
    claims = {"sub": "remote-uid", "cognito:username": "testuser"}
    user_getter.return_value = User(username="testuser")

    user = backends.SSOMigrationBackend().authenticate(
        request=None, claims={"sub": "remote-uid", "cognito:username": "testuser"}
    )
    assert user.username == "testuser"
    user_getter.assert_called_with(username="testuser", remote=None)
    create_remoteuser.assert_called_with(user, claims)


def test_ssomigration_not_exists(user_getter, create_remoteuser):
    claims = {"sub": "remote-uid", "cognito:username": "testuser"}
    user_getter.side_effect = ObjectDoesNotExist

    user = backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    assert user is None
    user_getter.assert_called_with(username="testuser", remote=None)
    assert not create_remoteuser.called


def test_ssomigration_inactive(user_getter, create_remoteuser):
    claims = {"sub": "remote-uid", "cognito:username": "testuser"}
    user_getter.return_value = User(username="testuser", is_active=False)

    with pytest.raises(PermissionDenied):
        backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    user_getter.assert_called_with(username="testuser", remote=None)
    assert not create_remoteuser.called

from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.core.exceptions import MultipleObjectsReturned
from nens_auth_client import backends

import pytest


@pytest.fixture
def user_getter(mocker):
    UserModel = mocker.patch("nens_auth_client.backends.UserModel")
    return UserModel.objects.get


@pytest.fixture
def create_remote_user(mocker):
    return mocker.patch("nens_auth_client.backends.create_remote_user")


def test_remote_user_exists(user_getter):
    user_getter.return_value = User(username="testuser")

    user = backends.RemoteUserBackend().authenticate(
        request=None, claims={"sub": "remote-uid"}
    )
    assert user.username == "testuser"
    user_getter.assert_called_with(remote__external_user_id="remote-uid")


def test_remote_user_not_exists(user_getter):
    user_getter.side_effect = ObjectDoesNotExist

    user = backends.RemoteUserBackend().authenticate(
        request=None, claims={"sub": "remote-uid"}
    )
    assert user is None
    user_getter.assert_called_with(remote__external_user_id="remote-uid")


def test_remote_user_inactive(user_getter):
    user_getter.return_value = User(username="testuser", is_active=False)

    with pytest.raises(PermissionDenied):
        backends.RemoteUserBackend().authenticate(
            request=None, claims={"sub": "remote-uid"}
        )
    user_getter.assert_called_with(remote__external_user_id="remote-uid")


def test_ssomigration_no_from_sso_claim(user_getter, create_remote_user):
    claims = {"sub": "remote-uid", "cognito:username": "testuser"}
    user_getter.return_value = User(username="testuser")

    user = backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    assert user is None


def test_ssomigration_wrong_from_sso_claim(user_getter, create_remote_user):
    claims = {
        "sub": "remote-uid",
        "cognito:username": "testuser",
        "custom:from_sso": "0",
    }
    user_getter.return_value = User(username="testuser")

    user = backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    assert user is None


def test_ssomigration_exists(user_getter, create_remote_user):
    claims = {
        "sub": "remote-uid",
        "cognito:username": "testuser",
        "custom:from_sso": "1",
        "email": "testuser@nelen-schuurmans.nl",
    }
    user_getter.return_value = User(
        username="testuser",
        email="testuser@nelen-schuurmans.nl"
    )

    user = backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    assert user.username == "testuser"
    user_getter.assert_called_with(
        username__iexact="testuser",
        email__iexact="testuser@nelen-schuurmans.nl"
    )
    create_remote_user.assert_called_with(user, claims)


def test_ssomigration_not_exists(user_getter, create_remote_user):
    claims = {
        "sub": "remote-uid",
        "cognito:username": "testuser",
        "custom:from_sso": "1",
        "email": "testuser@nelen-schuurmans.nl",
    }
    user_getter.side_effect = ObjectDoesNotExist

    user = backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    assert user is None
    user_getter.assert_called_with(
        username__iexact="testuser",
        email__iexact="testuser@nelen-schuurmans.nl"
    )
    assert not create_remote_user.called


def test_ssomigration_multiple_exist(user_getter, create_remote_user):
    claims = {
        "sub": "remote-uid",
        "cognito:username": "testuser",
        "custom:from_sso": "1",
        "email": "testuser@nelen-schuurmans.nl",
    }
    user_getter.side_effect = MultipleObjectsReturned

    with pytest.raises(PermissionDenied):
        backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    user_getter.assert_called_with(
        username__iexact="testuser",
        email__iexact="testuser@nelen-schuurmans.nl"
    )
    assert not create_remote_user.called


def test_ssomigration_inactive(user_getter, create_remote_user):
    claims = {
        "sub": "remote-uid",
        "cognito:username": "testuser",
        "custom:from_sso": "1",
        "email": "testuser@nelen-schuurmans.nl",
    }
    user_getter.return_value = User(username="testuser", is_active=False)

    with pytest.raises(PermissionDenied):
        backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    user_getter.assert_called_with(
        username__iexact="testuser",
        email__iexact="testuser@nelen-schuurmans.nl"
    )
    assert not create_remote_user.called


def test_ssomigration_no_username_claim(user_getter, create_remote_user):
    claims = {"sub": "remote-uid", "custom:from_sso": "1"}
    user_getter.return_value = User(username="testuser")

    user = backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    assert user is None


def test_ssomigration_google_nens_ok(user_getter, create_remote_user):
    claims = {
        "sub": "remote-uid",
        "cognito:username": "foo",
        "email": "testuser@nelen-schuurmans.nl",
        "email_verified": True,
        "identities": [{"providerName": "Google"}],
    }
    user_getter.return_value = User(username="testuser")

    user = backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    assert user.username == "testuser"
    user_getter.assert_called_with(
        username__iexact="testuser",
        email__iexact="testuser@nelen-schuurmans.nl"
    )
    create_remote_user.assert_called_with(user, claims)


@pytest.mark.parametrize(
    "claims",
    [
        {
            "email": "testuser@nelen-schuurmans.nl",
            "identities": [{"providerName": "Google"}],
        },
        {
            "email": "testuser@nelen-schuurmans.nl",
            "email_verified": False,
            "identities": [{"providerName": "Google"}],
        },
        {"email_verified": True, "identities": [{"providerName": "Google"}]},
        {
            "email": "testuser@other-domain.nl",
            "email_verified": True,
            "identities": [{"providerName": "Google"}],
        },
        {"email": "testuser@nelen-schuurmans.nl", "email_verified": True},
        {
            "email": "testuser@nelen-schuurmans.nl",
            "email_verified": True,
            "identities": [],
        },
        {
            "email": "testuser@nelen-schuurmans.nl",
            "email_verified": True,
            "identities": [{}],
        },
        {
            "email": "testuser@nelen-schuurmans.nl",
            "email_verified": True,
            "identities": [{"providerName": "NotGoogle"}],
        },
    ],
)
def test_ssomigration_google_nens_not_ok(user_getter, create_remote_user, claims):
    claims = {"sub": "remote-uid", "cognito:username": "foo", **claims}
    user_getter.return_value = User(username="testuser")

    user = backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    assert user is None

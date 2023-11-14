from django.contrib.auth.models import User
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import PermissionDenied
from nens_auth_client import backends

import pytest


@pytest.fixture
def user_getter(mocker):
    UserModel = mocker.patch("nens_auth_client.backends.UserModel")
    return UserModel.objects.get


@pytest.fixture
def user_getter_and_creater(mocker):
    # Using two separate fixtures for getter and creater doesn't work as we
    # work on the same ".objects".
    UserModel = mocker.patch("nens_auth_client.backends.UserModel")
    return UserModel.objects.get, UserModel.objects.create


@pytest.fixture
def create_remote_user(mocker):
    return mocker.patch("nens_auth_client.backends.create_remote_user")


@pytest.fixture
def create_user(mocker):
    return mocker.patch("nens_auth_client.backends.create_user")


@pytest.fixture
def m_permission_backend(mocker):
    cls = mocker.patch("nens_auth_client.permissions.DjangoPermissionBackend")
    return cls.return_value


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
        username="testuser", email="testuser@nelen-schuurmans.nl"
    )

    user = backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    assert user.username == "testuser"
    user_getter.assert_called_with(
        username__iexact="testuser", email__iexact="testuser@nelen-schuurmans.nl"
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
        username__iexact="testuser", email__iexact="testuser@nelen-schuurmans.nl"
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
        username__iexact="testuser", email__iexact="testuser@nelen-schuurmans.nl"
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
        username__iexact="testuser", email__iexact="testuser@nelen-schuurmans.nl"
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
        username__iexact="testuser", email__iexact="testuser@nelen-schuurmans.nl"
    )
    create_remote_user.assert_called_with(user, claims)


def test_ssomigration_google_nens_ok_even_capitalized(user_getter, create_remote_user):
    # Some smartypants created users with @Nelen-Schuurmans.nl...
    # Detect capitalized domain name, too.
    claims = {
        "sub": "remote-uid",
        "cognito:username": "foo",
        "email": "testuser@Nelen-Schuurmans.nl",
        "email_verified": True,
        "identities": [{"providerName": "Google"}],
    }
    user_getter.return_value = User(username="testuser")

    user = backends.SSOMigrationBackend().authenticate(request=None, claims=claims)
    assert user.username == "testuser"
    user_getter.assert_called_with(
        username__iexact="testuser", email__iexact="testuser@Nelen-Schuurmans.nl"
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


def test_accept_nens_nonexisting(user_getter_and_creater, create_remote_user):
    user_getter, user_creater = user_getter_and_creater
    claims = {
        "sub": "remote-uid",
        "cognito:username": "tuinplant",
        "email": "tuinplant@nelen-schuurmans.nl",
        "email_verified": True,
        "identities": [{"providerName": "NelenSchuurmans"}],
    }
    user_getter.side_effect = ObjectDoesNotExist
    user_creater.return_value = User(
        username="tuinplant", email="tuinplant@nelen-schuurmans.nl"
    )
    user = backends.AcceptNensBackend().authenticate(request=None, claims=claims)
    user_creater.assert_called_with(
        username="tuinplant", email="tuinplant@nelen-schuurmans.nl"
    )
    assert user.username == "tuinplant"
    create_remote_user.assert_called_with(user, claims)


def test_accept_nens_non_nens():
    # Reject non-nens users.
    claims = {
        "sub": "remote-uid",
        "cognito:username": "someone",
        "email": "someone@example.org",
        "email_verified": True,
        "identities": [{"providerName": "something"}],
    }
    user = backends.AcceptNensBackend().authenticate(request=None, claims=claims)
    assert user is None


def test_accept_nens_inactive(user_getter):
    claims = {
        "sub": "remote-uid",
        "cognito:username": "tuinplant",
        "email": "tuinplant@nelen-schuurmans.nl",
        "email_verified": True,
        "identities": [{"providerName": "NelenSchuurmans"}],
    }
    user_getter.return_value = User(
        username="tuinplant", email="tuinplant@nelen-schuurmans.nl", is_active=False
    )
    with pytest.raises(PermissionDenied):
        backends.AcceptNensBackend().authenticate(request=None, claims=claims)


def test_accept_nens_multiple(user_getter):
    claims = {
        "sub": "remote-uid",
        "cognito:username": "tuinplant",
        "email": "tuinplant@nelen-schuurmans.nl",
        "email_verified": True,
        "identities": [{"providerName": "NelenSchuurmans"}],
    }
    user_getter.side_effect = MultipleObjectsReturned
    with pytest.raises(PermissionDenied):
        backends.AcceptNensBackend().authenticate(request=None, claims=claims)


def test_trusted_backend_accepted(user_getter, settings, create_remote_user):
    # Accept the user that matches the criteria.
    settings.NENS_AUTH_TRUSTED_PROVIDERS = ["vanrees"]
    claims = {
        "sub": "remote-uid",
        "cognito:username": "goede.klant",
        "email": "goede.klant@vanrees.org",
        "identities": [{"providerName": "vanrees"}],
    }
    user_getter.return_value = User(
        username="goede_klant", email="goede.klant@vanrees.org", is_active=True
    )
    user = backends.TrustedProviderMigrationBackend().authenticate(
        request=None, claims=claims
    )
    assert user.username == "goede_klant"
    create_remote_user.assert_called_with(user, claims)


def test_trusted_backend_not_trusted():
    # Don't authenticate users frum untrusted backends.
    claims = {
        "sub": "remote-uid",
        "cognito:username": "someone",
        "email": "someone@example.org",
        "identities": [{"providerName": "something"}],
    }
    user = backends.TrustedProviderMigrationBackend().authenticate(
        request=None, claims=claims
    )
    assert user is None


def test_trusted_backend_inactive(user_getter, settings):
    # A user that's inactive should get a PermissionDenied.
    settings.NENS_AUTH_TRUSTED_PROVIDERS = ["vanrees"]
    claims = {
        "sub": "remote-uid",
        "cognito:username": "goede.klant",
        "email": "goede.klant@vanrees.org",
        "identities": [{"providerName": "vanrees"}],
    }
    user_getter.return_value = User(
        username="goede_klant", email="goede.klant@vanrees.org", is_active=False
    )
    with pytest.raises(PermissionDenied):
        backends.TrustedProviderMigrationBackend().authenticate(
            request=None, claims=claims
        )


def test_trusted_backend_multiple(user_getter, settings):
    # An email that's the email of multiple users? PermissionDenied.
    settings.NENS_AUTH_TRUSTED_PROVIDERS = ["vanrees"]
    claims = {
        "sub": "remote-uid",
        "cognito:username": "goede.klant",
        "email": "goede.klant@vanrees.org",
        "identities": [{"providerName": "vanrees"}],
    }
    user_getter.side_effect = MultipleObjectsReturned
    with pytest.raises(PermissionDenied):
        backends.TrustedProviderMigrationBackend().authenticate(
            request=None, claims=claims
        )


def test_trusted_backend_nonexisting_user(user_getter, settings):
    # An email that's not found on any existing user? Don't authenticate.
    settings.NENS_AUTH_TRUSTED_PROVIDERS = ["vanrees"]
    claims = {
        "sub": "remote-uid",
        "cognito:username": "goede.klant",
        "email": "goede.klant@vanrees.org",
        "identities": [{"providerName": "vanrees"}],
    }
    user_getter.side_effect = ObjectDoesNotExist
    user = backends.TrustedProviderMigrationBackend().authenticate(
        request=None, claims=claims
    )
    assert user is None


@pytest.mark.parametrize(
    "claims",
    [
        {
            "email": "testuser@nelen-schuurmans.nl",
        },
        {
            "identities": [{"providerName": "Google"}],
        },
    ],
)
def test_trusted_backend_proper_prerequisites(claims):
    # The claims need both email and providerName
    user = backends.TrustedProviderMigrationBackend().authenticate(
        request=None, claims=claims
    )
    assert user is None


def test_auto_permissions_backend_accepted(settings, create_user, m_permission_backend):
    # Accept the user that matches the criteria.
    settings.NENS_AUTH_AUTO_PERMISSIONS = {"goedeKlant": {"roles": ["user"]}}
    claims = {
        "sub": "remote-uid",
        "cognito:username": "pietje",
        "email": "piet@goede-klant.nl",
        "identities": [{"providerName": "goedeKlant"}],
    }
    create_user.return_value = User(
        username="goede_klant", email="piet@vanrees.org", is_active=True
    )
    user = backends.AutoPermissionBackend().authenticate(request=None, claims=claims)
    assert user.username == "goede_klant"
    create_user.assert_called_once_with(claims)
    m_permission_backend.assign.assert_called_once_with(
        permissions={"roles": ["user"]}, user=user
    )


def test_auto_permissions_backend_rejected(settings, create_user, m_permission_backend):
    # Accept the user that matches the criteria.
    settings.NENS_AUTH_AUTO_PERMISSIONS = {"goedeKlant": None}
    claims = {
        "sub": "remote-uid",
        "cognito:username": "pietje",
        "email": "piet@goede-klant.nl",
        "identities": [{"providerName": "andereKlant"}],
    }
    actual = backends.AutoPermissionBackend().authenticate(request=None, claims=claims)
    assert actual is None
    assert not create_user.called
    assert not m_permission_backend.called

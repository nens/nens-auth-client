from django.contrib.auth.models import User
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from nens_auth_client import backends

import pytest


@pytest.fixture
def user_getter(mocker):
    UserModel = mocker.patch("nens_auth_client.backends.UserModel")
    return UserModel.objects.get


@pytest.fixture
def socialuser_create(mocker):
    SocialUser = mocker.patch("nens_auth_client.backends.SocialUser")
    return SocialUser.objects.create


@pytest.mark.parametrize(
    "backend", [backends.SocialUserBackend, backends.EmailVerifiedBackend]
)
def test_get_user(user_getter, backend):
    user_getter.return_value = User(username="testuser")

    user = backend().get_user(42)
    assert user.username == "testuser"
    user_getter.assert_called_with(pk=42)


@pytest.mark.parametrize(
    "backend", [backends.SocialUserBackend, backends.EmailVerifiedBackend]
)
def test_get_user_inactive(user_getter, backend):
    user_getter.return_value = User(username="testuser", is_active=False)

    user = backend().get_user(42)
    assert user is None
    user_getter.assert_called_with(pk=42)


def test_socialuser_exists(user_getter):
    user_getter.return_value = User(username="testuser")

    user = backends.SocialUserBackend().authenticate(
        request=None, verified_id_token={"sub": "social-uid"}
    )
    assert user.username == "testuser"
    user_getter.assert_called_with(social__uid="social-uid")


def test_socialuser_not_exists(user_getter):
    user_getter.side_effect = ObjectDoesNotExist

    user = backends.SocialUserBackend().authenticate(
        request=None, verified_id_token={"sub": "social-uid"}
    )
    assert user is None
    user_getter.assert_called_with(social__uid="social-uid")


def test_emailverified_exists(user_getter, socialuser_create):
    user_getter.return_value = User(username="testuser")

    user = backends.EmailVerifiedBackend().authenticate(
        request=None,
        verified_id_token={
            "sub": "social-uid",
            "email": "a@b.com",
            "email_verified": True,
        },
    )
    assert user.username == "testuser"
    user_getter.assert_called_with(email__iexact="a@b.com")
    socialuser_create.assert_called_with(uid="social-uid", user=user)


def test_emailverified_not_exists(user_getter, socialuser_create):
    user_getter.side_effect = ObjectDoesNotExist

    user = backends.EmailVerifiedBackend().authenticate(
        request=None,
        verified_id_token={
            "sub": "social-uid",
            "email": "a@b.com",
            "email_verified": True,
        },
    )
    assert user is None
    user_getter.assert_called_with(email__iexact="a@b.com")
    assert not socialuser_create.called


def test_emailverified_multiple_exist(user_getter, socialuser_create):
    user_getter.side_effect = MultipleObjectsReturned

    user = backends.EmailVerifiedBackend().authenticate(
        request=None,
        verified_id_token={
            "sub": "social-uid",
            "email": "a@b.com",
            "email_verified": True,
        },
    )

    assert user is None
    user_getter.assert_called_with(email__iexact="a@b.com")
    assert not socialuser_create.called


@pytest.mark.parametrize(
    "token",
    [
        {"sub": "social-uid", "email": "a@b.com", "email_verified": False},
        {"sub": "social-uid", "email": "a@b.com"},
        {"sub": "social-uid", "email": "", "email_verified": True},
        {"sub": "social-uid", "email_verified": True},
    ],
)
def test_emailverified_no_verified_email(user_getter, socialuser_create, token):
    user = backends.EmailVerifiedBackend().authenticate(
        request=None, verified_id_token=token
    )
    assert user is None
    assert not user_getter.called
    assert not socialuser_create.called

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
def socialuser_create(mocker):
    SocialUser = mocker.patch("nens_auth_client.backends.SocialUser")
    return SocialUser.objects.create


def test_socialuser_exists(user_getter):
    user_getter.return_value = User(username="testuser")

    user = backends.SocialUserBackend().authenticate(
        request=None, userinfo={"sub": "social-uid"}
    )
    assert user.username == "testuser"
    user_getter.assert_called_with(social__external_user_id="social-uid")


def test_socialuser_not_exists(user_getter):
    user_getter.side_effect = ObjectDoesNotExist

    user = backends.SocialUserBackend().authenticate(
        request=None, userinfo={"sub": "social-uid"}
    )
    assert user is None
    user_getter.assert_called_with(social__external_user_id="social-uid")


def test_emailverified_exists(user_getter):
    user_getter.return_value = User(username="testuser")

    user = backends.EmailVerifiedBackend().authenticate(
        request=None,
        userinfo={
            "sub": "social-uid",
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
            "sub": "social-uid",
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
            "sub": "social-uid",
            "email": "a@b.com",
            "email_verified": True,
        },
    )

    assert user is None
    user_getter.assert_called_with(email__iexact="a@b.com")


@pytest.mark.parametrize(
    "userinfo",
    [
        {"sub": "social-uid", "email": "a@b.com", "email_verified": False},
        {"sub": "social-uid", "email": "a@b.com"},
        {"sub": "social-uid", "email": "", "email_verified": True},
        {"sub": "social-uid", "email_verified": True},
    ],
)
def test_emailverified_no_verified_email(user_getter, userinfo):
    user = backends.EmailVerifiedBackend().authenticate(
        request=None, userinfo=userinfo
    )
    assert user is None
    assert not user_getter.called


def test_create_socialuser(socialuser_create):
    user = User(id=42, username="testuser")
    user.backend = None
    backends.create_socialuser(user, {"sub": "abc"})
    socialuser_create.assert_called_with(user=user, external_user_id="abc")


def test_create_socialuser_skip(socialuser_create):
    user = User(id=42, username="testuser")
    user.backend = backends.SOCIALUSERBACKEND_PATH
    backends.create_socialuser(user, {"sub": "abc"})
    assert not socialuser_create.called


def test_create_socialuser_race_condition(socialuser_create):
    user = User(id=42, username="testuser")
    user.backend = None
    socialuser_create.side_effect = IntegrityError

    # ignores the IntegrityError:
    backends.create_socialuser(user, {"sub": "abc"})
    assert socialuser_create.called

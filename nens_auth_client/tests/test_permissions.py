from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import ValidationError
from nens_auth_client.permissions import DjangoPermissionBackend
from unittest import mock

import logging
import pytest


@pytest.fixture
def permissions():
    return {"user_permissions": [["add_invite", "nens_auth_client", "invite"]]}


@pytest.fixture
def Permission_m(mocker):
    return mocker.patch("nens_auth_client.permissions.Permission")


def test_validate_permissions(permissions, Permission_m):
    Permission_m.objects.get_by_natural_key.return_value = "bar"
    DjangoPermissionBackend().validate(permissions)
    Permission_m.objects.get_by_natural_key.assert_called_with(
        "add_invite", "nens_auth_client", "invite"
    )


def test_validate_permissions_non_existing(permissions, Permission_m):
    Permission_m.objects.get_by_natural_key.side_effect = ObjectDoesNotExist
    with pytest.raises(ValidationError):
        DjangoPermissionBackend().validate(permissions)
    Permission_m.objects.get_by_natural_key.assert_called_with(
        "add_invite", "nens_auth_client", "invite"
    )


@pytest.mark.parametrize(
    "permissions",
    [
        [],
        {"user_permissions": "not a list"},
        {"user_permissions": ["add_invite", "nens_auth_client", "invite"]},
        {"user_permissions": [["add_invite", "nens_auth_client"]]},
        {"user_permissions": [["add", "invite", "nens_auth_client", "invite"]]},
    ],
)
def test_validate_permissions_fails(permissions):
    with pytest.raises(ValidationError):
        DjangoPermissionBackend().validate(permissions)


def test_assign_permissions(permissions, Permission_m):
    user = mock.Mock()
    Permission_m.objects.get_by_natural_key.return_value = "bar"
    DjangoPermissionBackend().assign(permissions, user)
    Permission_m.objects.get_by_natural_key.assert_called_with(
        "add_invite", "nens_auth_client", "invite"
    )
    user.user_permissions.add.assert_called_with(["bar"])


def test_assign_permissions_skips_nonexisting(permissions, Permission_m, caplog):
    user = mock.Mock()
    Permission_m.objects.get_by_natural_key.side_effect = ObjectDoesNotExist
    DjangoPermissionBackend().assign(permissions, user)
    user.user_permissions.add.assert_called_with([])

    assert caplog.record_tuples == [
        (
            "nens_auth_client.permissions",
            logging.WARNING,
            "Skipped assigning non-existing permission ['add_invite', 'nens_auth_client', 'invite']",
        )
    ]

import logging
from unittest import mock

import pytest
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import ValidationError

from nens_auth_client.permissions import DjangoPermissionBackend


@pytest.fixture
def permissions():
    return {"user_permissions": [["add_invitation", "nens_auth_client", "invitation"]]}


@pytest.fixture
def Permission_m(mocker):
    return mocker.patch("nens_auth_client.permissions.Permission")


def test_validate_permissions(permissions, Permission_m):
    Permission_m.objects.get_by_natural_key.return_value = "bar"
    DjangoPermissionBackend().validate(permissions)
    Permission_m.objects.get_by_natural_key.assert_called_with(
        "add_invitation", "nens_auth_client", "invitation"
    )


def test_validate_permissions_non_existing(permissions, Permission_m):
    Permission_m.objects.get_by_natural_key.side_effect = ObjectDoesNotExist
    with pytest.raises(ValidationError):
        DjangoPermissionBackend().validate(permissions)
    Permission_m.objects.get_by_natural_key.assert_called_with(
        "add_invitation", "nens_auth_client", "invitation"
    )


@pytest.mark.parametrize(
    "permissions",
    [
        [],
        {"user_permissions": "not a list"},
        {"user_permissions": ["add_invitation", "nens_auth_client", "invitation"]},
        {"user_permissions": [["add_invitation", "nens_auth_client"]]},
        {"user_permissions": [["add", "invitation", "nens_auth_client", "invitation"]]},
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
        "add_invitation", "nens_auth_client", "invitation"
    )
    user.user_permissions.add.assert_called_with("bar")


def test_assign_permissions_skips_nonexisting(permissions, Permission_m, caplog):
    user = mock.Mock()
    Permission_m.objects.get_by_natural_key.side_effect = ObjectDoesNotExist
    DjangoPermissionBackend().assign(permissions, user)
    user.user_permissions.add.assert_called_with()

    assert caplog.record_tuples == [
        (
            "nens_auth_client.permissions",
            logging.WARNING,
            "Skipped assigning non-existing permission ['add_invitation', 'nens_auth_client', 'invitation']",
        )
    ]

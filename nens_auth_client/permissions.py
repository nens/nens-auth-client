# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.contrib.auth.models import Permission
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import ValidationError

import logging


logger = logging.getLogger(__name__)


def validate_permissions(permissions):
    """Validate invite permissions.

    This function can be overriden by changing NENS_AUTH_VALIDATE_PERMISSIONS

    It is validated that permissions is a dict and contains a key
    "user_permissions" that has a list of  contain a list of
        natural keys natural key (<codename>, <app>, <model>)

      {"user_permissions":  [["add_invite", "nens_auth_client", "invite"]]}
    """
    if not isinstance(permissions, dict):
        raise ValidationError("Invite permissions should be a dictionary")
    user_permission_keys = permissions.get("user_permissions", [])
    non_existing = []
    if not isinstance(user_permission_keys, list):
        raise ValidationError("user_permissions is not a list")
    for permission_key in user_permission_keys:
        if not isinstance(permission_key, list) or len(permission_key) != 3:
            raise ValidationError(
                "A user_permission is not a length-3 list. Every user_permission should contain 3 elements: [<codename>, <app>, <model>]."
            )
        try:
            Permission.objects.get_by_natural_key(*permission_key)
        except (TypeError, ObjectDoesNotExist):
            non_existing.append(permission_key)
    if non_existing:
        raise ValidationError("Permissions {} do not exist".format(non_existing))


def assign_permissions(permissions, user):
    """Assign permissions from an invite to a user.

    This function can be overriden by changing NENS_AUTH_ASSIGN_PERMISSIONS

    Args:
      permissions (dict): see validate_permissions
      user (User): requires 'user_permissions ManyToMany field
    """
    user_permission_keys = permissions.get("user_permissions", [])
    user_permission_objs = []
    for permission_key in user_permission_keys:
        try:
            user_permission_objs.append(
                Permission.objects.get_by_natural_key(*permission_key)
            )
        except ObjectDoesNotExist:
            logger.warning(
                "Skipped assigning non-existing permission %s", permission_key
            )
    user.user_permissions.add(user_permission_objs)

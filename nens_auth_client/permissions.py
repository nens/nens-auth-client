# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.contrib.auth.models import Permission
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import ValidationError

import logging


logger = logging.getLogger(__name__)


class DjangoPermissionBackend:
    """This class bundles functions to validate and assign invitation permissions.

    This class serves as an example implementation. It can be overriden with
    the NENS_AUTH_PERMISSION_BACKEND setting.
    """

    def validate(self, permissions):
        """Validate invitation permissions.

        It is validated that permissions is a dict and contains only the key
        "user_permissions" that has a list of Permission natural keys
        (<<codename>, <app>, <model>)

        Args:
          permissions (dict)

        Example:
          {"user_permissions":  [["add_invitation", "nens_auth_client", "invitation"]]}
        """
        if not isinstance(permissions, dict):
            raise ValidationError("Invitation permissions should be a dictionary")
        if len(permissions) == 0:
            return  # no keys is OK
        elif permissions.keys() != {"user_permissions"}:
            raise ValidationError(
                "Invitation permissions should contain only 'user_permissions'"
            )
        user_permission_keys = permissions["user_permissions"]
        non_existing = []
        if not isinstance(user_permission_keys, list):
            raise ValidationError("user_permissions is not a list")
        for permission_key in user_permission_keys:
            if not isinstance(permission_key, list) or len(permission_key) != 3:
                raise ValidationError(
                    "A user_permission is not a length-3 list. Every "
                    "user_permission should contain 3 elements: [<codename>, <app>, <model>]."
                )
            try:
                Permission.objects.get_by_natural_key(*permission_key)
            except (TypeError, ObjectDoesNotExist):
                non_existing.append(permission_key)
        if non_existing:
            raise ValidationError("Permissions {} do not exist".format(non_existing))

    def assign(self, permissions, user):
        """Assign permissions from an invitation to a user.

        Args:
          permissions (dict): see validate()
          user (model.Model): requires user_permissions ManyToMany field
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
        user.user_permissions.add(*user_permission_objs)

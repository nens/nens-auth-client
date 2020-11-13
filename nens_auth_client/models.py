# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.conf import settings
from django.contrib.auth.models import Permission
from django.core import serializers
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.db import models
from django.utils.crypto import get_random_string
from django.utils.module_loading import import_string
from functools import partial

# A known caveat of django-appconf is that we need to import the AppConf here
from nens_auth_client.conf import NensAuthClientAppConf  # NOQA

import json
import logging


logger = logging.getLogger(__name__)
user_model = getattr(settings, "AUTH_USER_MODEL", None) or "auth.User"


class RemoteUser(models.Model):
    """Associates an external user with a local user"""

    user = models.ForeignKey(
        user_model, related_name="remote", on_delete=models.CASCADE
    )
    external_user_id = models.CharField(
        max_length=255,
        db_index=True,
        unique=True,
        help_text="The user ID in the external identity provider, which is present as the 'sub' field in tokens.",
    )
    created = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.external_user_id


def _validate_permissions(value):
    func = import_string(settings.NENS_AUTH_VALIDATE_PERMISSIONS)
    func(json.loads(value))


class Invite(models.Model):
    id = models.CharField(
        primary_key=True, max_length=32, default=partial(get_random_string, 32)
    )
    PENDING = 0
    ACCEPTED = 1
    REJECTED = 2
    REVOKED = 3
    FAILED = 4
    INVITE_STATUS_CHOICES = [
        (PENDING, "Pending"),
        (ACCEPTED, "Accepted"),
        (REJECTED, "Rejected"),
        (REVOKED, "Revoked"),
        (FAILED, "Failed"),
    ]
    status = models.SmallIntegerField(choices=INVITE_STATUS_CHOICES, default=PENDING)
    expires = models.DateTimeField()
    user = models.ForeignKey(
        user_model, null=True, related_name="invites_received", on_delete=models.CASCADE
    )
    created_by = models.ForeignKey(
        user_model, null=True, related_name="invites_sent", on_delete=models.CASCADE
    )
    # Note that we do not use postgres' JSONField. Some projects use sqlite.
    permissions = models.TextField(
        default="{}",
        validators=[_validate_permissions],
        help_text=(
            "The permissions to be created after an invite is accepted, as a "
            "JSON object. In the default nens-auth-client implementation, "
            "django built-in user permissions are expected."
        ),
    )

    def __str__(self):
        return self.id

    def _update_status(self, status):
        self.status = status
        self.save(update_fields=["status"])

    def accept(self, user, **kwargs):
        func = import_string(settings.NENS_AUTH_ASSIGN_PERMISSIONS)
        try:
            result = func(permissions=json.loads(self.permissions), user=user, **kwargs)
        except Exception:
            self._update_status(Invite.FAILED)
            raise
        else:
            self._update_status(Invite.ACCEPTED)
            return result

    def reject(self):
        self._update_status(Invite.REJECTED)

    def revoke(self):
        self._update_status(Invite.REVOKED)


def validate_permissions(permissions):
    """Validate invite permissions.

    This function can be overriden by changing NENS_AUTH_VALIDATE_PERMISSIONS

    It is validated that permissions is a dict and contains a key
    "user_permissions" that has a list of  contain a list of
        natural keys natural key (<codename>, <app>, <model>)

      {"user_permissions":  [["add_invite", "nens_auth_client", "invite"]]}

    Args:
      permissions (dict): 
    <model>), like for example:
    """
    if not isinstance(permissions, dict):
        raise ValidationError("Invite permissions should be a dictionary")
    try:
        user_permission_keys = permissions["user_permissions"]
    except KeyError:
        raise ValidationError("Permissions do not contain 'user_permissions'")
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
      permissions (dict)
      user (User)
    """
    user_permission_keys = permissions.get("user_permissions", [])
    user_permission_objs = []
    for permission_key in user_permission_keys:
        try:
            user_permission_objs.append(
                Permission.objects.get_by_natural_key(permission_key)
            )
        except ObjectDoesNotExist:
            logger.warning(
                "Skipped assigning non-existing permission %s", permission_key
            )
    user.user_permissions.add(permissions)

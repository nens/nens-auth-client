# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
import json

from django.core import serializers
from django.conf import settings
from django.db import models
from django.utils.crypto import get_random_string
# A known caveat of django-appconf is that we need to import the AppConf here
from nens_auth_client.conf import NensAuthClientAppConf  # NOQA


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
        help_text="The user ID in the external identity provider, which is present as the 'sub' field in tokens."
    )
    created = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.external_user_id


def validate_invite_roles(value):
    roles = json.loads(value)
    assert isinstance(roles, list)


class Invite(models.Model):
    id = models.CharField(
        primary_key=True, max_length=32,
    )
    user = models.ForeignKey(
        user_model, related_name="invites", on_delete=models.CASCADE
    )
    # Note that we do not use postgres' JSONField. Some projects use sqlite.
    roles = models.TextField(
        default="[]",
        validators=[validate_invite_roles],
        help_text="The role objects to be created after an invite is accepted.",
    )
    created = models.DateTimeField(auto_now_add=True)

    @classmethod
    def create_invite(cls, user_id, roles_dict=(), **kwargs):
        return Invite.objects.create(
            id=get_random_string(32),
            user_id=user_id,
            roles=json.dumps(roles_dict),
        )

    def create_roles(self):
        for obj in serializers.deserialize("json", self.roles):
            obj.save()

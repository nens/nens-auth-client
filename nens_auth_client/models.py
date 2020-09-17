# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import JSONField
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from django.db import models


user_model = getattr(settings, "AUTH_USER_MODEL", None) or "auth.User"


class SocialUser(models.Model):
    """Associates an external user (by uid) with a local user"""

    user = models.ForeignKey(
        user_model, related_name="social_user", on_delete=models.CASCADE
    )
    uid = models.CharField(max_length=255, db_index=True)
    extra_data = JSONField()
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.uid

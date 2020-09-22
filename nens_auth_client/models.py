# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.conf import settings
from django.db import models
# A known caveat of django-appconf is that we need to import the AppConf here
from nens_auth_client.conf import NensAuthClientAppConf  # NOQA


user_model = getattr(settings, "AUTH_USER_MODEL", None) or "auth.User"


class SocialUser(models.Model):
    """Associates an external user (by uid) with a local user"""

    user = models.ForeignKey(
        user_model, related_name="social_user", on_delete=models.CASCADE
    )
    uid = models.CharField(max_length=255, db_index=True)
    created = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.uid

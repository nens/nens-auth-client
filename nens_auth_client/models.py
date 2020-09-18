# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.conf import settings
from django.db import models
from django.core.exceptions import PermissionDenied
# A known caveat of django-appconf is that we need to import the AppConf here
from nens_auth_client.conf import NensAuthClientAppConf  # NOQA
from django.contrib.auth import get_user_model


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


def get_user_through_socialuser(userinfo):
    """Get a User instance through an existing SocialUser"""
    uid = userinfo[settings.NENS_AUTH_UID_FIELD]
    try:
        social = SocialUser.objects.select_related("user").get(uid=uid)
    except SocialUser.DoesNotExist:
        return

    return {"social": social, "user": social.user}


def get_user_by_verified_email(userinfo):
    """Get a User instance by its email (if email_verified = True)

    Raises PermissionDenied if multiple users with the same email are present
    """
    if not userinfo.get("email_verified", False):
        return

    User = get_user_model()
    try:
        user = User.objects.get(email__iexact=userinfo["email"])
    except User.DoesNotExist:
        return
    except User.MultipleObjectsReturned:
        raise PermissionDenied(
            "Multiple local users with the same email present"
        )

    return {"user": user}

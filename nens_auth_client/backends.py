from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from nens_auth_client.models import SocialUser

import logging


logger = logging.getLogger(__name__)

UserModel = get_user_model()


class BaseBackend:
    def _create_social_user(user, userinfo):
        uid = userinfo.get(settings.NENS_AUTH_UID_FIELD)
        if uid is None:
            raise PermissionDenied("No user-id supplied")
        try:
            return SocialUser.objects.create(uid=uid, user=user)
        except IntegrityError:
            # This race condition is expected to occur when the same user
            # calls /authenticate multiple times.
            pass

    # The following methods are compied from django.contrib.auth.ModelBackend:

    def user_can_authenticate(self, user):
        """
        Reject users with is_active=False. Custom user models that don't have
        that attribute are allowed.
        """
        is_active = getattr(user, "is_active", None)
        return is_active or is_active is None

    def get_user(self, user_id):
        try:
            user = UserModel._default_manager.get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None


class SocialUserBackend(BaseBackend):
    """Authenticate a user through an existing SocialUser
    """

    def authenticate(self, request, verified_id_token=None):
        uid = verified_id_token.get(settings.NENS_AUTH_UID_FIELD)
        if uid is None:
            raise PermissionDenied("No user-id supplied")
        try:
            user = UserModel.objects.get(social__uid=uid)
        except SocialUser.DoesNotExist:
            return
        return user


class EmailVerifiedBackend(BaseBackend):
    """Authenticate a user by email address (case-insensitive).

    A SocialUser will be created automatically if a user is found.

    When there are multiple users with the same email address, an error is
    raised.
    """

    def authenticate(self, request, verified_id_token):
        if not verified_id_token.get("email_verified", False):
            raise PermissionDenied("Email address is not verified")
        uid = verified_id_token.get(settings.NENS_AUTH_UID_FIELD)
        if uid is None:
            raise PermissionDenied("No user-id supplied")
        email = verified_id_token.get("email")
        if email is None:
            raise PermissionDenied("No email supplied")

        try:
            return UserModel.objects.get(email__iexact=email)
        except UserModel.DoesNotExist:
            return
        except UserModel.MultipleObjectsReturned:
            raise PermissionDenied(
                "Multiple users with the same email present ({})".format(email)
            )

from django.contrib.auth import get_user_model
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from nens_auth_client.models import SocialUser

import logging


logger = logging.getLogger(__name__)

UserModel = get_user_model()


class BaseBackend:
    def _create_social_user(self, user, verified_id_token):
        uid = verified_id_token["sub"]
        try:
            return SocialUser.objects.create(external_user_id=uid, user=user)
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
            user = UserModel.objects.get(pk=user_id)
        except ObjectDoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None


class SocialUserBackend(BaseBackend):
    """Authenticate a user through an existing SocialUser
    """

    def authenticate(self, request, verified_id_token=None):
        uid = verified_id_token["sub"]
        try:
            return UserModel.objects.get(social__external_user_id=uid)
        except ObjectDoesNotExist:
            return


class EmailVerifiedBackend(BaseBackend):
    """Authenticate a user by email address (case-insensitive).

    A SocialUser will be created automatically if a user is found.

    When there are multiple users with the same email address, an error is
    raised.
    """

    def authenticate(self, request, verified_id_token):
        if not verified_id_token.get("email_verified", False):
            return
        email = verified_id_token.get("email")
        if not email:
            return

        try:
            user = UserModel.objects.get(email__iexact=email)
        except (ObjectDoesNotExist, MultipleObjectsReturned):
            return

        self._create_social_user(user, verified_id_token)
        return user

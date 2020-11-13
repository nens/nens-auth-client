from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied

import logging


logger = logging.getLogger(__name__)

UserModel = get_user_model()


class RemoteUserBackend(ModelBackend):
    def authenticate(self, request, claims):
        """Authenticate a token through an existing RemoteUser

        Unlike the django ModelBackend, this backend raises a PermissionDenied
        if the user is inactive.

        Args:
          request: the current request
          claims (dict): the verified payload of the ID or Access token

        Returns:
          user or None
        """
        uid = claims["sub"]
        try:
            user = UserModel.objects.get(remote__external_user_id=uid)
        except ObjectDoesNotExist:
            return

        if not self.user_can_authenticate(user):
            raise PermissionDenied("User is inactive")

        return user


class EmailVerifiedBackend(ModelBackend):
    def authenticate(self, request, claims):
        """Authenticate a token by verified email address (case-insensitive).

        When there are multiple users with the same email address, no user is
        returned.

        Args:
          request: the current request
          claims (dict): the verified payload of the ID or Access token

        Returns:
          user or None
        """
        if not claims.get("email_verified", False):
            return
        email = claims.get("email")
        if not email:
            return

        try:
            user = UserModel.objects.get(email__iexact=email)
        except (ObjectDoesNotExist, MultipleObjectsReturned):
            return

        return user if self.user_can_authenticate(user) else None

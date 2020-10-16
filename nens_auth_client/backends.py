from .models import RemoteUser
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

import logging


logger = logging.getLogger(__name__)

UserModel = get_user_model()


class RemoteUserBackend(ModelBackend):
    def authenticate(self, request, claims):
        """Authenticate a token through an existing RemoteUser

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

        return user if self.user_can_authenticate(user) else None


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


# for usage in create_remoteuser
REMOTEUSERBACKEND_PATH = ".".join(
    [RemoteUserBackend.__module__, RemoteUserBackend.__name__]
)


def create_remoteuser(user, claims):
    """Permanently associate a user with an external id

    Creates a RemoteUser object if it does not exist already

    Args:
      user (User): the user to be associated. It should have a 'backend'
        attribute, which is set by django's authenticate() method.
      claims (dict): the verified payload of the ID or Access token
    """
    # If the user authenticated using the RemoteUserBackend, there must
    # already be a RemoteUser present. Do nothing in that case.
    if user.backend == REMOTEUSERBACKEND_PATH:
        return

    # Create a permanent association between local and external user
    try:
        RemoteUser.objects.create(external_user_id=claims["sub"], user=user)
    except IntegrityError:
        # This race condition is expected to occur when the same user
        # calls the authorize view multiple times.
        pass

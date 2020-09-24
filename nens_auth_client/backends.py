from .models import SocialUser
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError

import logging


logger = logging.getLogger(__name__)

UserModel = get_user_model()


class SocialUserBackend(ModelBackend):
    def authenticate(self, request, userinfo=None):
        """Authenticate a token through an existing SocialUser

        When there are multiple users with the same email address, no user is
        returned.

        Args:
          request: the current request
          userinfo (dict): the payload of the ID token

        Returns:
          user or None
        """
        uid = userinfo["sub"]
        try:
            return UserModel.objects.get(social__external_user_id=uid)
        except ObjectDoesNotExist:
            return


class EmailVerifiedBackend(ModelBackend):
    def authenticate(self, request, userinfo):
        """Authenticate a token by verified email address (case-insensitive).

        When there are multiple users with the same email address, no user is
        returned.

        Args:
          request: the current request
          userinfo (dict): the payload of the ID token

        Returns:
          user or None
        """
        if not userinfo.get("email_verified", False):
            return
        email = userinfo.get("email")
        if not email:
            return

        try:
            user = UserModel.objects.get(email__iexact=email)
        except (ObjectDoesNotExist, MultipleObjectsReturned):
            return

        return user


# for usage in create_socialuser
SOCIALUSERBACKEND_PATH = ".".join(
    [SocialUserBackend.__module__, SocialUserBackend.__name__]
)


def create_socialuser(user, userinfo):
    """Permanently associate a user with an external id

    Creates a SocialUser object if it does not exist already

    Args:
      user (User): the user to be associated. It should have a 'backend'
        attribute, which is set by django's authenticate() method.
      userinfo (dict): the payload of the ID token
    """
    # If the user authenticated using the SocialUserBackend, there must
    # already be a SocialUser present. Do nothing in that case.
    if user.backend == SOCIALUSERBACKEND_PATH:
        return

    # Create a permanent association between local and external user
    try:
        SocialUser.objects.create(external_user_id=userinfo["sub"], user=user)
    except IntegrityError:
        # This race condition is expected to occur when the same user
        # calls the authorize view multiple times.
        pass

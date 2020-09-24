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
    """Authenticate a user through an existing SocialUser
    """

    def authenticate(self, request, verified_id_token=None):
        uid = verified_id_token["sub"]
        try:
            return UserModel.objects.get(social__external_user_id=uid)
        except ObjectDoesNotExist:
            return


class EmailVerifiedBackend(ModelBackend):
    """Authenticate a user by verified email address (case-insensitive).

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

        return user


# for usage in create_socialuser
SocialUserBackend.import_path = ".".join(
    [SocialUserBackend.__module__, SocialUserBackend.__name__]
)


def create_socialuser(user, verified_id_token):
    """Permanently associate a user with an external id

    Creates a SocialUser object if it does not exist already"""
    # If the user authenticated using the SocialUserBackend, there must
    # already be a SocialUser present. Do nothing in that case.
    if user.backend == SocialUserBackend.import_path:
        return

    # Create a permanent association between local and external user
    try:
        SocialUser.objects.create(external_user_id=verified_id_token["sub"], user=user)
    except IntegrityError:
        # This race condition is expected to occur when the same user
        # calls the authorize view multiple times.
        pass

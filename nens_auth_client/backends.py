from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist

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

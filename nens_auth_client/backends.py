from .users import create_remote_user
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import PermissionDenied

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
            raise PermissionDenied(
                "Cannot authenticate the local user because it is set to inactive."
            )

        return user


class SSOMigrationBackend(ModelBackend):
    def authenticate(self, request, claims):
        """Temporary backend for users that were migrated from SSO to AWS.

        Previously, users were matched by username. We keep doing that for
        users that came from the SSO and have not been associated yet. Users
        that are migrated from the SSO are recognized by the claim
        "custom:from_sso" being 1.

        Args:
          request: the current request
          claims (dict): the verified payload of the ID or Access token

        Returns:
          user or None
        """
        username = claims.get("cognito:username")
        if not username:
            return
        allow_username_match = claims.get("custom:from_sso", 0)
        if int(allow_username_match) != 1:  # AWS formats integers as strings
            return

        try:
            user = UserModel.objects.get(username=username, remote=None)
        except ObjectDoesNotExist:
            return

        if not self.user_can_authenticate(user):
            raise PermissionDenied(
                "Cannot authenticate the local user because it is set to inactive."
            )

        # Create a permanent association
        create_remote_user(user, claims)

        return user if self.user_can_authenticate(user) else None

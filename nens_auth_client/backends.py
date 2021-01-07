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
        users that came from the SSO and have not been associated yet.

        Users that are migrated from the SSO are recognized by one of two
        things:

        - (normal accounts) "custom:from_sso" being 1.
        - (AD acounts) IDP = Google and email domain = @nelen-schuurmans.nl

        Args:
          request: the current request
          claims (dict): the verified payload of the ID or Access token

        Returns:
          user or None
        """
        allow_username_match = int(claims.get("custom:from_sso", 0)) == 1
        username = claims.get("cognito:username")
        if not allow_username_match:
            try:
                assert claims["identities"][0]["providerName"] == "Google"
                assert claims["email_verified"]
                username, domain = claims["email"].split("@")
                assert domain == "nelen-schuurmans.nl"
            except (KeyError, IndexError, AssertionError, ValueError):
                pass
            else:
                allow_username_match = True

        if not allow_username_match or not username:
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

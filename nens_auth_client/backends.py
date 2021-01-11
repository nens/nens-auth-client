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


def _nens_user_extract_username(claims):
    """Return the username from the email claim if the user is a N&S user.

    A N&S user is characterized by 1) coming from "Google" identity provider
    and 2) having (verified) email domain @nelen-schuurmans.nl.
    """
    # Get the provider name, return False if not present
    try:
        provider_name = claims["identities"][0]["providerName"]
    except (KeyError, IndexError):
        return

    if provider_name != "Google":
        return
    if not claims.get("email_verified", False):
        return

    # Unpack email
    username, domain = claims.get("email", "a@b").split("@", 1)
    if domain != "nelen-schuurmans.nl":
        return

    return username


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
        username = None
        if int(claims.get("custom:from_sso", 0)):
            username = claims.get("cognito:username")
        else:
            username = _nens_user_extract_username(claims)

        if username is None:
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

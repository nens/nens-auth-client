from .users import create_remote_user
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import MultipleObjectsReturned
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
            raise PermissionDenied(settings.NENS_AUTH_ERROR_USER_INACTIVE)

        return user


def _nens_user_extract_username(claims):
    """Return the username from the email claim if the user is a N&S user.

    A N&S user is characterized by 1) coming from either "Google" or
    "NelenSchuurmans" identity provider and 2) having (verified)
    email domain @nelen-schuurmans.nl.
    """
    # Get the provider name, return False if not present
    try:
        provider_name = claims["identities"][0]["providerName"]
    except (KeyError, IndexError):
        return

    if provider_name not in ("Google", "NelenSchuurmans"):
        return
    if not claims.get("email_verified", False):
        return

    # Unpack email
    username, domain = claims.get("email", "a@b").split("@", 1)
    if domain.lower() != "nelen-schuurmans.nl":
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
        - (AD acounts) IDP = Google or NelenSchuurmans, and
              email domain = @nelen-schuurmans.nl

        Args:
          request: the current request
          claims (dict): the verified payload of the ID or Access token

        Returns:
          user or None
        """
        username = None
        if int(claims.get("custom:from_sso", 0)) == 1:
            username = claims.get("cognito:username")
        else:
            username = _nens_user_extract_username(claims)

        if username is None:
            return

        email = claims.get("email")

        try:
            user = UserModel.objects.get(username__iexact=username, email__iexact=email)
        except ObjectDoesNotExist:
            return
        except MultipleObjectsReturned:
            raise PermissionDenied(settings.NENS_AUTH_ERROR_USER_MULTIPLE)

        if not self.user_can_authenticate(user):
            raise PermissionDenied(settings.NENS_AUTH_ERROR_USER_INACTIVE)

        # Create a permanent association
        create_remote_user(user, claims)

        return user


class TrustedProviderMigrationBackend(ModelBackend):
    """Backend for users that move from cognito to a new provider, like azure

    A company can ask to couple their identity provider (like azure AD) to our
    cognito instance. Often, their users will already have an existing
    account. This backend provides a means to automatically couple these
    "remote users" to their existing django user.

    The only useful way to couple them is by comparing the email address. So
    we should have a specific list of external providers that we trust to pass
    the correct email address.

    """

    def authenticate(self, request, claims):
        """Return user if a trusted provider provides a known email address

        The regular `RemoteUserBackend` authenticates existing remote
        users. What we should do is to check the following:

        - Is the user being authenticated by an external identity provider
        that we trust?

        - If so, is the email address known?

        Note that duplicate email addresses aren't acceptable: we'll raise an
        error. They should have been cleaned up beforehand.

        Args:
          request: the current request
          claims (dict): the verified payload of the ID or Access token

        Returns:
          user or None
        """
        try:
            # We need proper claims with provider_name and email, otherwise we
            # don't need to bother to look.
            provider_name = claims["identities"][0]["providerName"]
            email = claims["email"]
        except (KeyError, IndexError):
            return

        if provider_name not in TODO_LIST:
            logger.debug("%s not in special list of trusted providers", provider_name)
            return

        try:
            user = UserModel.objects.get(email__iexact=email)
        except ObjectDoesNotExist:
            return
        except MultipleObjectsReturned:
            raise PermissionDenied(settings.NENS_AUTH_ERROR_USER_MULTIPLE)

        if not self.user_can_authenticate(user):
            raise PermissionDenied(settings.NENS_AUTH_ERROR_USER_INACTIVE)

        # Create a permanent association
        create_remote_user(user, claims)

        return user


class AcceptNensBackend(ModelBackend):
    def authenticate(self, request, claims):
        """Backend for auto-accepting users that have a N&S azure AD account.

        The behaviour looks a bit like the SSOMigrationBackend above, but with
        two key differences:

        - N&S users don't need an existing account, they're accepted right
          away and a User is created if missing.

        - We only deal with users recognized as being really from N&S.

        Args:
          request: the current request
          claims (dict): the verified payload of the ID or Access token

        Returns:
          user or None

        """
        username = _nens_user_extract_username(claims)
        if username is None:
            return

        email = claims.get("email")

        try:
            # For our purposes, just a match on email is enough. Some
            # usernames have been shortened to fit within 20 characters though
            # the email has not, so we escape some corner cases this way.
            user = UserModel.objects.get(email__iexact=email)
        except ObjectDoesNotExist:
            user = UserModel.objects.create(
                username=username.lower(), email=email.lower()
            )
            logger.info("Auto-accepting new N&S user %s: created", username)
        except MultipleObjectsReturned:
            raise PermissionDenied(settings.NENS_AUTH_ERROR_USER_MULTIPLE)

        if not self.user_can_authenticate(user):
            raise PermissionDenied(settings.NENS_AUTH_ERROR_USER_INACTIVE)

        # Create a permanent association
        create_remote_user(user, claims)

        return user

from .users import _extract_provider_name
from .users import create_remote_user
from .users import create_user
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import MultipleObjectsReturned
from django.core.exceptions import ObjectDoesNotExist
from django.core.exceptions import PermissionDenied
from django.utils.module_loading import import_string

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
    provider_name = _extract_provider_name(claims)
    if not provider_name:
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
        provider_name = _extract_provider_name(claims)
        email = claims.get("email")
        # We need proper claims with provider_name and email, otherwise we
        # don't need to bother to look.
        if not provider_name or not email:
            return

        if provider_name not in settings.NENS_AUTH_TRUSTED_PROVIDERS:
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


class AutoPermissionBackend(ModelBackend):
    """Backend to autocreate users and permissions for selected providers.

    A company can ask to couple their identity provider (like azure AD) to our
    cognito instance. Sometimes, they do not want to send each of their users
    an invitation and instead provide a standard set of permissions to all of
    their users. This backend provides a means to do that.

    The backend should be configured *after* the RemoteUserBackend, otherwise
    a new user will be created each time a user logs in.

    The related setting is NENS_AUTH_AUTO_PERMISSIONS, which should be configured
    as a dict that maps provider_name to something that can be accepted by the
    invitation backend. For instance:

    NENS_AUTH_AUTO_PERMISSIONS = {"NelenSchuurmans": {"1": ["user"]}}
    """

    def authenticate(self, request, claims):
        """Return user if the provider is trusted.

        The regular `RemoteUserBackend` authenticates existing remote
        users. In case that didn't happen, we should create a new user if the
        provider is trusted.

        Args:
          request: the current request
          claims (dict): the verified payload of the ID or Access token

        Returns:
          user or None
        """
        provider_name = _extract_provider_name(claims)
        if (
            not provider_name
            or provider_name not in settings.NENS_AUTH_AUTO_PERMISSIONS
        ):
            return

        # Create user and remote user
        user = create_user(claims)

        # Optionally, set permissions
        permissions = settings.NENS_AUTH_AUTO_PERMISSIONS[provider_name]
        if permissions:
            permission_backend = import_string(settings.NENS_AUTH_PERMISSION_BACKEND)()
            permission_backend.assign(permissions=permissions, user=user)

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

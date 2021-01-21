from .models import RemoteUser
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import get_random_string

import logging

logger = logging.getLogger(__name__)


User = get_user_model()


def create_remote_user(user, claims):
    """Create RemoteUser to permanently associate a User with an external one.

    Args:
      user (User): the user to be associated
      claims (dict): the (verified) payload of an AWS Cognito ID token
    """
    external_id = claims["sub"]
    try:
        RemoteUser.objects.create(external_user_id=external_id, user=user)
    except IntegrityError:
        # This race condition is expected to occur when the same user
        # calls the authorize view multiple times.
        pass


def _create_user(username, external_id):
    """Atomically create a user and associate it to a given external user ID.

    Args:
      username (str): should be non-existing (else: IntegrityError)
      external_id (str): external user ID, can be existing, in which case this
        function does nothing.

    Returns:
      user or None if external_id already existed
    """
    try:
        with transaction.atomic():
            user = User.objects.create_user(username=username, password=None)
            RemoteUser.objects.create(external_user_id=external_id, user=user)
    except IntegrityError:
        # A race condition might occur when the same user authorizes twice
        # at the same time.
        if RemoteUser.objects.filter(external_user_id=external_id).exists():
            return

        # Unknown IntegrityErrors should be raised.
        raise

    return user


def create_user(claims):
    """Create User and associate it with an external one through RemoteUser.

    The username is taken from the "cognito:username" field.

    Raises an IntegrityError if this username already exists. This is expected
    to happen very rarely, in which case we do want to see this in our bug
    tracker.

    Args:
      claims (dict): the (verified) payload of an AWS Cognito ID token

    Returns:
      django User (created or, in case of a race condition, retrieved)
      RemoteUser (created or, in case of a race condition, retrieved)
    """
    # Format a username from the claims.
    username = ""
    if claims.get("identities"):
        # External identity providers result in usernames that are not
        # recognizable by the end user. Use the email instead.
        username = claims.get("email")
    if not username:
        username = claims["cognito:username"]
    username = username[: settings.NENS_AUTH_USERNAME_MAX_LENGTH]

    external_id = claims["sub"]
    try:
        return _create_user(username, external_id)
    except IntegrityError:
        # We probably hit a username unique constraint. Try again with
        # some added random characters.
        if User.objects.filter(username=username).exists():
            suffix = get_random_string(4)
            logger.warning(
                "Username '%s' already existed, appending '%s'.", username, suffix
            )
            return _create_user(username + suffix, external_id)

        # Unknown IntegrityErrors should be raised.
        raise


def update_user(user, claims):
    """Update a User's metadata from ID token claims (Cognito)

    Args:
      user (User): the user to be udpated
      claims (dict): the (verified) payload of an AWS Cognito ID token
    """
    user.first_name = claims.get("given_name", "")
    user.last_name = claims.get("family_name", "")
    if claims.get("email_verified"):
        user.email = claims.get("email", "")
    else:
        user.email = ""
    user.save()


def update_remote_user(claims, tokens):
    """Update a RemoteUser's metadata from the tokens

    Args:
      claims (dict): the (verified) payload of an AWS Cognito ID token
      tokens (dict): the tokens (id_token, access_token, refresh_token)
    """
    external_id = claims["sub"]

    RemoteUser.objects.filter(external_user_id=external_id).update(
        id_token=tokens.get("id_token", ""),
        access_token=tokens.get("access_token", ""),
        refresh_token=tokens.get("refresh_token", ""),
        last_modified=timezone.now(),
    )

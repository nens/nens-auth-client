from django.contrib.auth import get_user_model
from .models import RemoteUser
from django.db import IntegrityError
from django.db import transaction
from django.core.exceptions import PermissionDenied


def create_remoteuser(user, claims):
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


def create_user(claims):
    """Create User and associate it with an external one through RemoteUser.

    Raises a PermissionDenied if the username already exists. The username
    is taken from the "cognito:username" field.

    Args:
      claims (dict): the (verified) payload of an AWS Cognito ID token

    Returns:
      django User (created or, in case of a race condition, retrieved)
    """
    User = get_user_model()
    username = claims["cognito:username"]
    external_id = claims["sub"]
    try:
        with transaction.atomic():
            user = User.objects.create_user(username=username, password=None)
            RemoteUser.objects.create(
                external_user_id=external_id, user=user
            )
        return user
    except IntegrityError:
        # A race condition is likely when the same user authorizes twice
        try:
            return User.objects.get(remote__external_user_id=external_id)
        except User.DoesNotExist:
            pass

        # Another option is that the username is already taken
        if User.objects.filter(username=username).exists():
            raise PermissionDenied("This username is already taken")

        # Unknown IntegrityErrors should be raised as such:
        raise


def update_user(user, claims):
    """Update a User's metadata from ID token claims (Cognito)

    Args:
      user (User): the user to be udpated
      claims (dict): the (verified) payload of an AWS Cognito ID token
    """
    user.first_name = claims.get("given_name", "")
    user.last_name = claims.get("family_name", "")
    user.email = claims["email"] if claims["email_verified"] else ""
    user.save()

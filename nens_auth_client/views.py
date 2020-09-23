# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# from nens_auth_client import models
from .oauth import oauth
from django.conf import settings
from django.db import IntegrityError
from django.http.response import JsonResponse
from nens_auth_client.models import SocialUser

import django.contrib.auth as django_auth


def login(request):
    """Initiate authentication through OpenID Connect

    The response is a redirect to AWS Cognito according to the OpenID Connect
    standard.

    TODO: What if the user is already logged in?
    TODO: add 'next' query parameter
    """
    cognito = oauth.create_client("cognito")
    return cognito.authorize_redirect(request, settings.NENS_AUTH_REDIRECT_URI)


def authorize(request):
    """Authorizes a user that authenticated through OpenID Connect.

    This is the callback url (a.k.a. redirect_uri) from the login view.

    TODO: Gracefully handle errors (instead of bare 403 / 500)
    TODO: Redirect to 'next' query parameter that was given on login
    TODO: Logic to match userinfo to local user if socialuser does not exist
    """
    cognito = oauth.create_client("cognito")
    token = cognito.authorize_access_token(request)
    userinfo = cognito.parse_id_token(request, token)

    # connect tot the django authentication backends
    user = django_auth.authenticate(request, verified_id_token=userinfo)

    if user is not None:
        # TODO: Is this the best place to put this logic?
        # TODO: Unittests
        # Create a permanent association between local and external user
        if (
            settings.NENS_AUTH_AUTO_CREATE_SOCIAL_USER
            and user.backend != "nens_auth_client.backends.SocialUserBackend"
        ):
            # Create a permanent association between local and external user
            try:
                SocialUser.objects.create(external_user_id=userinfo["sub"], user=user)
            except IntegrityError:
                # This race condition is expected to occur when the same user
                # calls the authorize view multiple times.
                pass

        # log the user in
        django_auth.login(request, user)

    # temporary response (handy for debugging)
    return JsonResponse({"user": getattr(user, "username", None), "id_token": userinfo})


def logout(request):
    """Logout the user (only locally)

    TODO: Also logout the user on AWS Cognito
    """
    username = request.user.username if request.user else None
    django_auth.logout(request)

    # temporary response (handy for debugging)
    return JsonResponse({"user": username})

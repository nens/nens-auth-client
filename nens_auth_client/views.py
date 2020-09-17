# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# from nens_auth_client import models
from .models import SocialUser
from .oauth import oauth
from django.http.response import JsonResponse
from django.conf import settings

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

    # TODO Logic to match userinfo to local user if socialuser does not exist
    try:
        user = SocialUser.objects.select_related("user").get(
            uid=userinfo["cognito:username"]
        ).user
    except SocialUser.DoesNotExist:
        user = None

    # log the user in (note that this call will error if there are multiple
    # authentication backends configured)
    if user is not None:
        django_auth.login(request, user)

    # temporary response (handy for debugging)
    return JsonResponse(
        {
            "user": request.user.username if request.user else None,
            "id_token": userinfo,
        }
    )


def logout(request):
    """Logout the user (only locally)

    TODO: Also logout the user on AWS Cognito
    """
    username = request.user.username if request.user else None
    django_auth.logout(request)

    # temporary response (handy for debugging)
    return JsonResponse({"user": username})

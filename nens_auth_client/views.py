# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# from nens_auth_client import models
import sys

from .oauth import oauth
from django.conf import settings
from django.http.response import JsonResponse

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


def _import_func(path):
    module_name, member = path.rsplit('.', 1)
    __import__(module_name)
    return getattr(sys.modules[module_name], member)


def associate_user(userinfo):
    for path in settings.NENS_AUTH_USER_ASSOCIATION_PIPELINE:
        func = _import_func(path)
        result = func(userinfo)
        if result is not None:
            userinfo.update(result)
    return userinfo


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

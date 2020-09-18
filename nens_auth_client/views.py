# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# from nens_auth_client import models
from .models import associate_user
from .oauth import oauth
from django.conf import settings
from django.http.response import JsonResponse
from django.http.response import HttpResponseRedirect

from django.contrib.auth import REDIRECT_FIELD_NAME
import django.contrib.auth as django_auth
from django.utils.http import is_safe_url

REDIRECT_SESSION_KEY = "nens_auth_redirect_to"


def _get_absolute_success_url(request):
    """Get the (absolute) success url from the 'next' parameter in the url

    Defaults to NENS_AUTH_DEFAULT_SUCCESS_URL.
    """
    if REDIRECT_FIELD_NAME in request.GET:
        redirect_to = request.build_absolute_uri(request.GET[REDIRECT_FIELD_NAME])
        if is_safe_url(
            url=redirect_to,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure(),
        ):
            return redirect_to

    # Default to NENS_AUTH_DEFAULT_SUCCESS_URL
    return request.build_absolute_uri(settings.NENS_AUTH_DEFAULT_SUCCESS_URL)


def login(request):
    """Initiate authentication through OpenID Connect

    The response is a redirect to AWS Cognito according to the OpenID Connect
    standard.

    The full flow goes as follows:

    1. https://xxx.lizard.net/login?next=/admin
    2. https://aws.cognito/login?...&redirect_uri=https://auth.lizard.net/authorize
    3. https://auth.lizard.net/authorize
    4. https://xxx.lizard.net/admin

    Note that /authorize is on a fixed domain (say, "auth.lizard.net"). This
    is imposed by AWS Cognito (it just checks redirect_uri). To account for the
    possibility that /login is on a different domain (say, "xxx.lizard.net"),
    the 'next' url is absolutized before storing in the session.
    """
    # Get the success redirect url
    success_url = _get_absolute_success_url(request)

    # If the user was already authenticated, redirect to the success url
    if request.user.is_authenticated:
        return HttpResponseRedirect(success_url)

    # Store the success_url in the session for later use
    request.session[REDIRECT_SESSION_KEY] = success_url

    # Redirect to the authorization server
    cognito = oauth.create_client("cognito")
    return cognito.authorize_redirect(request, settings.NENS_AUTH_REDIRECT_URI)


def authorize(request):
    """Authorizes a user that authenticated through OpenID Connect.

    This is the callback url (a.k.a. redirect_uri) from the login view.

    TODO: Gracefully handle errors (instead of bare 403 / 500)
    TODO: Logic to match userinfo to local user if socialuser does not exist
    """
    cognito = oauth.create_client("cognito")
    token = cognito.authorize_access_token(request)
    userinfo = cognito.parse_id_token(request, token)

    user = associate_user(userinfo)

    # log the user in (note that this call will error if there are multiple
    # authentication backends configured)
    if user is not None:
        django_auth.login(request, user)

    return HttpResponseRedirect(request.session[REDIRECT_SESSION_KEY])


def logout(request):
    """Logout the user (only locally)

    TODO: Also logout the user on AWS Cognito
    """
    username = request.user.username if request.user else None
    django_auth.logout(request)

    # temporary response (handy for debugging)
    return JsonResponse({"user": username})

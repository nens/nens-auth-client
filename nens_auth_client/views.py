# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# from nens_auth_client import models
from .models import associate_user
from .oauth import oauth
from urllib.parse import urlencode
from django.conf import settings
from django.http.response import JsonResponse
from django.http.response import HttpResponseRedirect

from django.contrib.auth import REDIRECT_FIELD_NAME
import django.contrib.auth as django_auth
from django.utils.http import is_safe_url

LOGIN_REDIRECT_SESSION_KEY = "nens_auth_login_redirect_to"
LOGOUT_REDIRECT_SESSION_KEY = "nens_auth_logout_redirect_to"


def _get_absolute_redirect_url(request, default):
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

    # Absolutize the default url
    return request.build_absolute_uri(default)


def login(request):
    """Initiate authentication through OpenID Connect

    The response is a redirect to AWS Cognito according to the OpenID Connect
    standard.

    The full flow goes as follows:

    1. https://xxx.lizard.net/login/?next=admin/
    2. https://aws.cognito/login/?...&redirect_uri=https://auth.lizard.net/authorize/
    3. https://auth.lizard.net/authorize/
    4. https://xxx.lizard.net/admin/

    Note that /authorize is on a fixed domain (say, "auth.lizard.net"). This
    is imposed by AWS Cognito (it just checks redirect_uri). To account for the
    possibility that /login is on a different domain (say, "xxx.lizard.net"),
    the 'next' url is absolutized before storing in the session.
    """
    # Get the success redirect url
    success_url = _get_absolute_redirect_url(
        request, default=settings.NENS_AUTH_DEFAULT_SUCCESS_URL
    )

    # If the user was already authenticated, redirect to the success url
    if request.user.is_authenticated:
        return HttpResponseRedirect(success_url)

    # Store the success_url in the session for later use
    request.session[LOGIN_REDIRECT_SESSION_KEY] = success_url

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

    return HttpResponseRedirect(request.session[LOGIN_REDIRECT_SESSION_KEY])


def logout(request):
    """Logout hte user (locally and remotely)

    The full flow goes as follows:

    1. https://xxx.lizard.net/logout/?next=/admin/
    2. https://aws.cognito/logout?...&redirect_uri=https://auth.lizard.net/logout/
    3. https://auth.lizard.net/logout/
    4. https://xxx.lizard.net/admin/

    Note that this view is called twice in this flow.
    """
    # Get the redirect url from the session (if step 3.)
    redirect_url = request.session.pop(LOGOUT_REDIRECT_SESSION_KEY, None)

    # Get the redirect url from the query params (if step 1.)
    if redirect_url is None:
        redirect_url = _get_absolute_redirect_url(
            request, default=settings.NENS_AUTH_DEFAULT_LOGOUT_URL
        )

    # In case of step 3. or if step 1. & user was not logged in: redirect
    if not request.user.is_authenticated:
        return HttpResponseRedirect(redirect_url)

    # Log the user out
    django_auth.logout(request)

    # Store the redirect_url in the session for later use
    request.session[LOGOUT_REDIRECT_SESSION_KEY] = redirect_url

    # Redirect to authorization server
    logout_url = "{}?client_id={}&logout_uri={}".format(
        settings.NENS_AUTH_LOGOUT_URL,
        settings.NENS_AUTH_CLIENT_ID,
        settings.NENS_AUTH_LOGOUT_REDIRECT_URI,
    )
    return HttpResponseRedirect(logout_url)

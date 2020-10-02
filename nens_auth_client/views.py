# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# from nens_auth_client import models
from .backends import create_remoteuser
from .oauth import oauth_registry
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.exceptions import PermissionDenied
from django.http.response import HttpResponseRedirect
from django.urls import reverse
from django.utils.http import is_safe_url
from django.views.decorators.cache import cache_control

import django.contrib.auth as django_auth


LOGIN_REDIRECT_SESSION_KEY = "nens_auth_login_redirect_to"
LOGOUT_REDIRECT_SESSION_KEY = "nens_auth_logout_redirect_to"


def _get_redirect_url(request):
    """Get the redirect url from the 'next' parameter in the url and check
    if it is safe.
    """
    if REDIRECT_FIELD_NAME in request.GET:
        redirect_to = request.GET[REDIRECT_FIELD_NAME]
        if is_safe_url(
            url=redirect_to,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure(),
        ):
            return redirect_to


@cache_control(no_store=True)
def login(request):
    """Initiate authentication through OpenID Connect

    The response is a redirect to AWS Cognito according to the OpenID Connect
    standard.

    The full flow goes as follows:

    1. https://x.lizard.net/login/?next=/admin/
    2. https://aws.cognito/login/?...&redirect_uri=https://x.lizard.net/authorize/
    3. https://x.lizard.net/authorize/
    4. https://x.lizard.net/admin/

    Note that a list of all (absolute) redirect URIs
    (e.g. "https://auth.lizard.net/authorize/") need to be registered with
    AWS Cognito. Wildcards are not allowed because of security reasons.

    At the same time we need the redirect to go to the correct subdomain or
    else cookies will not be valid.
    """
    # Get the success redirect url
    success_url = _get_redirect_url(request) or settings.NENS_AUTH_DEFAULT_SUCCESS_URL

    # If the user was already authenticated, redirect to the success url
    if request.user.is_authenticated:
        return HttpResponseRedirect(success_url)

    # Store the success_url in the session for later use
    request.session[LOGIN_REDIRECT_SESSION_KEY] = success_url

    # Redirect to the authorization server
    cognito = oauth_registry.create_client("cognito")

    redirect_uri = request.build_absolute_uri(reverse(authorize))
    return cognito.authorize_redirect(request, redirect_uri)


@cache_control(no_store=True)
def authorize(request):
    """Authorizes a user that authenticated through OpenID Connect.

    This is the callback url (a.k.a. redirect_uri) from the login view.

    TODO: Gracefully handle errors (instead of bare 403 / 500)
    TODO: Cache the JWKS request
    """
    cognito = oauth_registry.create_client("cognito")
    token = cognito.authorize_access_token(request)
    claims = cognito.parse_id_token(request, token)

    # The django authentication backend(s) should find a local user
    user = django_auth.authenticate(request, claims=claims)

    if user is None:
        raise PermissionDenied("No user found with this idenity")

    # Log the user in
    django_auth.login(request, user)

    # Create a permanent association between local and external users
    if settings.NENS_AUTH_AUTO_CREATE_REMOTE_USER:
        create_remoteuser(user, claims)

    return HttpResponseRedirect(request.session[LOGIN_REDIRECT_SESSION_KEY])


@cache_control(no_store=True)
def logout(request):
    """Logout the user (locally and remotely)

    The full flow goes as follows:

    1. https://xxx.lizard.net/logout/?next=/admin/
    2. https://aws.cognito/logout?...&redirect_uri=https://auth.lizard.net/logout/
    3. https://auth.lizard.net/logout/
    4. https://xxx.lizard.net/admin/

    Note that this view is called twice in this flow.
    """
    if not request.user.is_authenticated:
        # We are in step 3. (user is already logged out)
        redirect_url = request.session.pop(LOGOUT_REDIRECT_SESSION_KEY, None)
        if redirect_url is None:
            # If there is nothing in the session, the user called /logout
            # without being logged in in the first place. Just use the 'next'
            # parameter.
            redirect_url = _get_redirect_url(request) or settings.NENS_AUTH_DEFAULT_LOGOUT_URL
        return HttpResponseRedirect(redirect_url)

    # Log the user out
    django_auth.logout(request)

    # Store the redirect_url in the session for later use
    request.session[LOGOUT_REDIRECT_SESSION_KEY] = _get_redirect_url(request) or settings.NENS_AUTH_DEFAULT_LOGOUT_URL

    # Redirect to authorization server
    logout_url = "{}?client_id={}&logout_uri={}".format(
        settings.NENS_AUTH_LOGOUT_URL,
        settings.NENS_AUTH_CLIENT_ID,
        request.build_absolute_uri(reverse(logout)),
    )
    return HttpResponseRedirect(logout_url)

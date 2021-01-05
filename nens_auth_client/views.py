# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# from nens_auth_client import models
from . import users
from .backends import RemoteUserBackend
from .models import Invitation
from .oauth import get_oauth_client
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.exceptions import PermissionDenied
from django.http.response import HttpResponseNotFound
from django.http.response import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.http import is_safe_url
from django.views.decorators.cache import cache_control
from urllib.parse import urlencode

import django.contrib.auth as django_auth


LOGIN_REDIRECT_SESSION_KEY = "nens_auth_login_redirect_to"
INVITATION_KEY = "nens_auth_invitation_slug"
LOGOUT_REDIRECT_SESSION_KEY = "nens_auth_logout_redirect_to"
REMOTE_USER_BACKEND_PATH = ".".join(
    [RemoteUserBackend.__module__, RemoteUserBackend.__name__]
)


def _get_redirect_from_next(request, default):
    """Return redirect url from the "next" parameter in the url

    Returns the default if there is no "next" parameter or if it is unsafe.
    """
    if REDIRECT_FIELD_NAME in request.GET:
        redirect_to = request.GET[REDIRECT_FIELD_NAME]
        if is_safe_url(
            url=redirect_to,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure(),
        ):
            return redirect_to

    return default


@cache_control(no_store=True)
def login(request):
    """Initiate authentication through OpenID Connect.

    See the README for a description of the OpenID Connect login flow.

    Query parameters:
      next: the URL to redirect to on authorization success. If absolute, it
        must match the domain of this request. Optional, default is set by
        settings.NENS_AUTH_DEFAULT_SUCCESS_URL
      invitation: an optional Invitation id. On authorization success, a user will be
        created and permissions from the Invitation are applied.

    Response:
      HTTP 302 Redirect to AWS Cognito (according to the OpenID Connect standard)
      A session cookie will be included.

    Note that a list of all (absolute) redirect URIs
    (e.g. "https://my.site/authorize/") must be registered with
    AWS Cognito. Wildcards are not allowed because of security reasons. At
    the same time we need the redirect to go to the correct subdomain or
    else cookies will not be valid.
    """
    # Get the success redirect url
    success_url = _get_redirect_from_next(
        request, default=settings.NENS_AUTH_DEFAULT_SUCCESS_URL
    )

    # If the user was already authenticated, redirect to the success url
    if request.user.is_authenticated:
        return HttpResponseRedirect(success_url)

    # Store the success_url in the session for later use
    request.session[LOGIN_REDIRECT_SESSION_KEY] = success_url

    # Store the invitation-key (if present)
    request.session[INVITATION_KEY] = request.GET.get("invitation", None)

    # Redirect to the authorization server
    client = get_oauth_client()
    redirect_uri = request.build_absolute_uri(
        reverse(settings.NENS_AUTH_URL_NAMESPACE + "authorize")
    )
    return client.authorize_redirect(request, redirect_uri)


@cache_control(no_store=True)
def authorize(request):
    """Authorizes a user that authenticated through OpenID Connect.

    See the README for a description of the OpenID Connect login flow.
    This is the callback url (a.k.a. redirect_uri) from the login view.

    Response:
      HTTP 302 Redirect to the 'next' query parameter (see login view)

    Raises:
    - ``authlib.jose.errors.JoseError``: cryptographic errors
      The error details must never be shown to the user.
    - ``authlib.integrations.base_client.errors.OAuthError``: OAuth2 errors.
      These are defined in https://tools.ietf.org/html/rfc6749#section-4.1.2.1.
      The error descriptions can be shown to the user.
    - ``django.core.exceptions.PermissionDenied``: authorization errors.
      This error is raised when no user is present to log in and there is no
      acceptable invitation.
    """
    client = get_oauth_client()
    client.check_error_in_query_params(request)
    tokens = client.authorize_access_token(request, timeout=settings.NENS_AUTH_TIMEOUT)
    claims = client.parse_id_token(request, tokens, leeway=settings.NENS_AUTH_LEEWAY)

    # The RemoteUserBackend finds a local user through a RemoteUser
    user = django_auth.authenticate(request, claims=claims)

    # If nothing was found: only a valid invitation warrants a new user association
    if user is None and INVITATION_KEY in request.session:
        try:
            invitation = Invitation.objects.select_related("user").get(
                slug=request.session[INVITATION_KEY]
            )
        except Invitation.DoesNotExist:
            raise PermissionDenied("No invitation matches the given query.")
        invitation.check_acceptability()  # May raise PermissionDenied
        if invitation.user is not None:
            # associate permanently
            user = invitation.user
            users.create_remote_user(user, claims)
        else:
            # create user and associate permanently
            user = users.create_user(claims)

        user.backend = REMOTE_USER_BACKEND_PATH  # needed for login

    # No user, no login
    if user is None:
        raise PermissionDenied("No user found with this idenity")

    # Update the user's metadata fields
    users.update_user(user, claims)
    users.update_remote_user(claims, tokens)

    # Log the user in
    django_auth.login(request, user)

    return HttpResponseRedirect(request.session[LOGIN_REDIRECT_SESSION_KEY])


@cache_control(no_store=True)
def logout(request):
    """Logout the user (locally and remotely)

    See the README for a description of the logout flow. Note that this view
    is called twice in this flow.

    Query parameters:
      next: the URL to redirect to after logout. If absolute, it
        must match the domain of this request. Optional, default is set by
        settings.NENS_AUTH_DEFAULT_LOGOUT_URL

    Response:
    - if user is logged in locally: HTTP 302 Redirect to the remote logout URL.
      The user is logged out and the 'next' query parameter is stored in the session.
    - if user is logged out locally: HTTP 302 Redirect to the 'next' query parameter
    """
    if not request.user.is_authenticated:
        # We are in step 3. (user is already logged out)
        redirect_url = request.session.pop(LOGOUT_REDIRECT_SESSION_KEY, None)
        if redirect_url is None:
            # If there is nothing in the session, the user called /logout
            # without being logged in in the first place. Just use the 'next'
            # parameter.
            redirect_url = _get_redirect_from_next(
                request, default=settings.NENS_AUTH_DEFAULT_LOGOUT_URL
            )
        return HttpResponseRedirect(redirect_url)

    # Log the user out
    django_auth.logout(request)

    # Store the redirect_url in the session for later use
    request.session[LOGOUT_REDIRECT_SESSION_KEY] = _get_redirect_from_next(
        request, default=settings.NENS_AUTH_DEFAULT_LOGOUT_URL
    )

    # Redirect to authorization server
    logout_uri = request.build_absolute_uri(
        reverse(settings.NENS_AUTH_URL_NAMESPACE + "logout")
    )
    client = get_oauth_client()
    return client.logout_redirect(request, logout_uri)


@cache_control(no_store=True)
def accept_invitation(request, slug):
    """Assign the permissions of an Invitation to the current user.

    If there is no current user, first redirect to the login view, adding
    'next' and 'invitation' query parameters. The 'invitation' parameter makes sure
    that a user will be created if necessary. The 'next' parameter makes sure
    that the user will return here after successful login.

    The full flow is described in the README.
    """
    # First check if the invitation is there and if it is still acceptable
    invitation = get_object_or_404(Invitation, slug=slug)

    try:
        invitation.check_acceptability()  # May raise PermissionDenied
    except PermissionDenied as e:
        return HttpResponseNotFound(str(e))

    # We need a user - redirect to login view if user is not authenticated
    if not request.user.is_authenticated:
        login_url = reverse(settings.NENS_AUTH_URL_NAMESPACE + "login")
        query_params = {"invitation": slug, "next": request.get_full_path()}
        return HttpResponseRedirect(login_url + "?" + urlencode(query_params))

    invitation.accept(request.user)
    success_url = _get_redirect_from_next(
        request, default=settings.NENS_AUTH_DEFAULT_SUCCESS_URL
    )
    return HttpResponseRedirect(success_url)

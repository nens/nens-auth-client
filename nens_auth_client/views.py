# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# from nens_auth_client import models
from . import permissions
from . import users
from .backends import RemoteUserBackend
from .models import Invitation
from .oauth import get_oauth_client
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.core.exceptions import PermissionDenied
from django.http.response import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse

try:
    from django.utils.http import url_has_allowed_host_and_scheme
except ImportError:
    from django.utils.http import is_safe_url as url_has_allowed_host_and_scheme

from authlib.integrations.base_client.errors import MismatchingStateError
from authlib.integrations.base_client.errors import OAuthError
from django.views.decorators.cache import never_cache
from urllib.parse import urlencode

import django.contrib.auth as django_auth

LOGIN_REDIRECT_SESSION_KEY = "nens_auth_login_redirect_to"
INVITATION_KEY = "nens_auth_invitation_slug"
LOGOUT_REDIRECT_SESSION_KEY = "nens_auth_logout_redirect_to"
REMOTE_USER_BACKEND_PATH = ".".join(
    [RemoteUserBackend.__module__, RemoteUserBackend.__name__]
)


def _get_redirect_from_next(request):
    """Return redirect url from the "next" parameter in the url.

    Returns None if there is no "next" parameter or if it is unsafe.
    """
    if REDIRECT_FIELD_NAME in request.GET:
        redirect_to = request.GET[REDIRECT_FIELD_NAME]
        if url_has_allowed_host_and_scheme(
            url=redirect_to,
            allowed_hosts={request.get_host()},
            require_https=request.is_secure(),
        ):
            return redirect_to


@never_cache
def login(request):
    """Initiate authentication through OpenID Connect.

    See the README for a description of the OpenID Connect login flow.

    Query parameters:
      next: the URL to redirect to on authorization success. If absolute, it
        must match the domain of this request. Optional, default is set by
        settings.NENS_AUTH_DEFAULT_SUCCESS_URL
      invitation: an optional Invitation id. On authorization success, a user will be
        created and permissions from the Invitation are applied.
      force_logout: if "true", force local and remote logout

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
    success_url = _get_redirect_from_next(request)

    # Whether to force logout or not
    force_logout = request.GET.get("force_logout") == "true"
    if force_logout:
        django_auth.logout(request)
    elif request.user.is_authenticated:
        # If the user was already authenticated, redirect to the success url
        return HttpResponseRedirect(
            success_url or settings.NENS_AUTH_DEFAULT_SUCCESS_URL
        )

    # Store the success_url in the session for later use (if present)
    if success_url:
        request.session[LOGIN_REDIRECT_SESSION_KEY] = success_url

    # Store the invitation-key (if present)
    invitation = request.GET.get("invitation")
    if invitation:
        request.session[INVITATION_KEY] = invitation

    # Redirect to the authorization server
    client = get_oauth_client()
    redirect_uri = request.build_absolute_uri(
        reverse(settings.NENS_AUTH_URL_NAMESPACE + "authorize")
    )

    if force_logout:
        return client.logout_redirect(request, redirect_uri, login_after=True)
    else:
        return client.authorize_redirect(request, redirect_uri)


def _get_login_url(request):
    """Reverse engineer the login URL from the current session

    This includes adding the "next" parameter from the session. The "invitation"
    is not reproduced from the session (because that would be a security leak).
    """
    success_url = request.session.get(LOGIN_REDIRECT_SESSION_KEY)
    params = {}
    if success_url:
        params[REDIRECT_FIELD_NAME] = success_url
    login_url = (
        request.build_absolute_uri(reverse(settings.NENS_AUTH_URL_NAMESPACE + "login"))
        + "?"
        + urlencode(params)
    )
    return login_url


@never_cache
def authorize(request):
    """Authorizes a user that authenticated through OpenID Connect.

    See the README for a description of the OpenID Connect login flow.
    This is the callback url (a.k.a. redirect_uri) from the login view.

    Response:
      normally:

      HTTP 302 Redirect to the 'next' query parameter (see login view)

      invalid state / expired code:

      HTTP 302 Redirect to the login view ('next' parameter is persisted, but
      the invitation is not)

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
    # client.check_error_in_query_params(request)
    try:
        tokens = client.authorize_access_token(
            request, timeout=settings.NENS_AUTH_TIMEOUT
        )
    except MismatchingStateError:
        # This happens mostly when people use the browser 'back' and 'forward' buttons
        # --> Retry the complete login flow. There are several cases:
        # - the user is already logged in locally (login view will redirect to success url)
        # - the user is already logged in on cognito (not locally): login view will redirect to
        #   cognito which will (without user intervention) redirect back to here, now
        #   with a correct state & fresh code
        # - the user is not logged in: cognito will prompt for credentials and redirect here
        return HttpResponseRedirect(_get_login_url(request))

    except OAuthError as e:
        if e.error == "invalid_grant":
            # This happens when the code has been used already, also due to misuse of 'back' and
            # 'forward' buttons. See above for more notes.
            return HttpResponseRedirect(_get_login_url(request))
        raise e
    claims = tokens.pop("userinfo")

    # The RemoteUserBackend finds a local user through a RemoteUser
    user = django_auth.authenticate(request, claims=claims)

    if user is None:
        # Get the invitation from the session. Also remove it as an invitation
        # may be used only once. So it should not remain in the session.
        invitation_slug = request.session.pop(INVITATION_KEY, None)

        # No user and no invitation: no login
        if not invitation_slug:
            raise PermissionDenied(settings.NENS_AUTH_ERROR_USER_DOES_NOT_EXIST)

        try:
            invitation = Invitation.objects.select_related("user").get(
                slug=invitation_slug
            )
        except Invitation.DoesNotExist:
            raise PermissionDenied(settings.NENS_AUTH_ERROR_INVITATION_DOES_NOT_EXIST)
        # May raise PermissionDenied:
        invitation.check_acceptability(email=claims.get("email") or None)
        if invitation.user is not None:
            # associate permanently
            user = invitation.user
            users.create_remote_user(user, claims)
        else:
            # create user and associate permanently
            user = users.create_user(claims)

        user.backend = REMOTE_USER_BACKEND_PATH  # needed for login

    # Update the user's metadata fields
    users.update_user(user, claims)
    users.update_remote_user(claims, tokens)

    # Automatically assign permissions based on the user's claims
    permissions.auto_assign_permissions(user, claims)

    # Log the user in
    django_auth.login(request, user)

    # Redirect to the success url stored in session (or use default)
    success_url = request.session.get(
        LOGIN_REDIRECT_SESSION_KEY, settings.NENS_AUTH_DEFAULT_SUCCESS_URL
    )
    return HttpResponseRedirect(success_url)


@never_cache
def logout(request):
    """Logout the user (locally and remotely)

    See the README for a description of the logout flow.

    Query parameters:
      next: the URL to redirect to after logout-success. If absolute, it
        must match the domain of this request. Optional, default is set by
        settings.NENS_AUTH_DEFAULT_LOGOUT_URL

    Response:
    - if user is logged in locally: HTTP 302 Redirect to the remote logout URL.
      The user is logged out and the 'next' query parameter is stored in the session.
    """
    # Log the user out
    django_auth.logout(request)

    # Store the redirect_url in the session for later use (if present)
    redirect_url = _get_redirect_from_next(request)
    if redirect_url:
        request.session[LOGOUT_REDIRECT_SESSION_KEY] = redirect_url

    # Redirect to authorization server
    logout_uri = request.build_absolute_uri(
        reverse(settings.NENS_AUTH_URL_NAMESPACE + "logout-success")
    )
    client = get_oauth_client()
    return client.logout_redirect(request, logout_uri)


@never_cache
def logout_success(request):
    """Callback url for logout.

    See the README for a description of the logout flow.

    Query parameters:
      next: the URL to redirect to after logout. If absolute, it
        must match the domain of this request. Optional, default is set by
        settings.NENS_AUTH_DEFAULT_LOGOUT_URL

    Response:
    - if user is logged out locally: HTTP 302 Redirect to the 'next' query parameter
      that is stored in the session (or default logout url if unavailable).
    - if user is logged in locally: HTTP 302 Redirect to the logout view
    """
    # If a user is still authenticated: this should not happen. Return 403.
    if request.user.is_authenticated:
        raise PermissionDenied("Logout failure")

    redirect_url = request.session.get(
        LOGOUT_REDIRECT_SESSION_KEY, settings.NENS_AUTH_DEFAULT_LOGOUT_URL
    )
    return HttpResponseRedirect(redirect_url)


@never_cache
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

    # We need a user - redirect to login view if user is not authenticated.
    # The acceptability of the invitation is checked in the login view.
    if not request.user.is_authenticated:
        login_url = reverse(settings.NENS_AUTH_URL_NAMESPACE + "login")
        query_params = {"invitation": slug, "next": request.get_full_path()}
        return HttpResponseRedirect(login_url + "?" + urlencode(query_params))

    # Check if the invitation is acceptable (including if email matches)
    # If the current user has no email this check is skipped
    invitation.check_acceptability(email=request.user.email or None)
    invitation.accept(request.user)
    success_url = _get_redirect_from_next(request)
    return HttpResponseRedirect(success_url or settings.NENS_AUTH_DEFAULT_SUCCESS_URL)

# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
# from nens_auth_client import models
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
from django.utils.http import is_safe_url
from django.views.decorators.cache import cache_control
from urllib.parse import urlencode

import django.contrib.auth as django_auth


LOGIN_REDIRECT_SESSION_KEY = "nens_auth_login_redirect_to"
INVITE_KEY = "nens_auth_invitation_slug"
LOGOUT_REDIRECT_SESSION_KEY = "nens_auth_logout_redirect_to"


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
    """Initiate authentication through OpenID Connect

    The full flow goes as follows:

    1. https://x.lizard.net/login/?next=/admin/&invitation=1234abcd
    2. https://aws.cognito/login/?...&redirect_uri=https://x.lizard.net/authorize/
    3. https://x.lizard.net/authorize/
    4. https://x.lizard.net/admin/

    Query parameters:
      next: the URL to redirect to on authorization success. If absolute, it
        must match the domain of this request. Optional, default is set by
        settings.NENS_AUTH_DEFAULT_SUCCESS_URL
      invitation: an optional Invitation id. On authorization success, a user will be
        created and permissions from the Invitation are applied.

    The response is a redirect to AWS Cognito according to the OpenID Connect
    standard.

    Note that a list of all (absolute) redirect URIs
    (e.g. "https://auth.lizard.net/authorize/") need to be registered with
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
    request.session[INVITE_KEY] = request.GET.get("invitation", None)

    # Redirect to the authorization server
    client = get_oauth_client()
    redirect_uri = request.build_absolute_uri(
        reverse(settings.NENS_AUTH_URL_NAMESPACE + "authorize")
    )
    return client.authorize_redirect(request, redirect_uri)


@cache_control(no_store=True)
def authorize(request):
    """Authorizes a user that authenticated through OpenID Connect.

    This is the callback url (a.k.a. redirect_uri) from the login view.

    Raises:
    - ``authlib.jose.errors.JoseError``: cryptographic errors
      The error details must never be shown to the user.
    - ``authlib.integrations.base_client.errors.OAuthError``: OAuth2 errors.
      These are defined in https://tools.ietf.org/html/rfc6749#section-4.1.2.1.
      The error descriptions can be shown to the user.
    - ``django.core.exceptions.PermissionDenied``: authorization errors.
      This error is raised when no user is present to log in.
    """
    client = get_oauth_client()
    client.check_error_in_query_params(request)
    token = client.authorize_access_token(request, timeout=settings.NENS_AUTH_TIMEOUT)
    claims = client.parse_id_token(request, token, leeway=settings.NENS_AUTH_LEEWAY)

    # The RemoteUserBackend finds a local user through a RemoteUser
    user = django_auth.authenticate(request, claims=claims)

    # If nothing was found: only a valid invitation warrants a new user association
    if user is None and INVITE_KEY in request.session:
        try:
            invitation = Invitation.objects.select_related("user").get(
                slug=request.session[INVITE_KEY], status=Invitation.PENDING
            )
        except Invitation.DoesNotExist:
            raise PermissionDenied("Invalid invitation key")
        if invitation.user is not None:
            # associate permanently
            user = invitation.user
            users.create_remote_user(user, claims)
        else:
            # create user and associate permanently
            user = users.create_user(claims)

        user.backend = RemoteUserBackend  # needed for login

    # No user, no login
    if user is None:
        raise PermissionDenied("No user found with this idenity")

    # Update the user's metadata fields
    users.update_user(user, claims)

    # Log the user in
    django_auth.login(request, user)

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
def accept_invitation(request, invitation):
    """Assign the permissions of an Invitation to the current user.

    If there is no current user, first redirect to the login view, adding
    'next' and 'invitation' query parameters. The 'invitation' parameter makes sure
    that a user will be created if necessary. The 'next' parameter makes sure
    that the user will return here after successful login.

    The full flow goes as follows:

    1. https://xxx.lizard.net/invitations/abc123/accept/?next=/admin/
    2. https://xxx.lizard.net/login/?invitation=abc123&next=%2Finvitations%2Fabc123%2Faccept%2F%3Fnext%3D%2Fadmin%2F
    3. https://aws.cognito/login?...&redirect_uri=https://auth.lizard.net/authorize/
    4. https://xxx.lizard.net/authorize/
    5. https://xxx.lizard.net/invitations/abc123/accept/?next=/admin/
    6. https://xxx.lizard.net/admin/

    If the user was already logged in, only steps 5 and 6 are done.
    """
    # Redirect to login view if user is not authenticated
    if not request.user.is_authenticated:
        login_url = reverse(settings.NENS_AUTH_URL_NAMESPACE + "login")
        query_params = {"invitation": invitation, "next": request.get_full_path()}
        return HttpResponseRedirect(login_url + "?" + urlencode(query_params))

    invitation = get_object_or_404(Invitation, slug=invitation, status=Invitation.PENDING)
    invitation.accept(request.user)
    success_url = _get_redirect_from_next(
        request, default=settings.NENS_AUTH_DEFAULT_SUCCESS_URL
    )
    return HttpResponseRedirect(success_url)

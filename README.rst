nens-auth-client
==========================================

Introduction
------------

This library defines the necessary views and models to connect the AWS Cognito
user pool to the local django user database.

Usage: general
--------------

The nens-auth-client library exposes one django application: ``nens_auth_client``.
The django built-in apps ``auth``, ``sessions`` and ``contenttypes`` are
also required, but they probably are already there.
Add these to the ``INSTALLED_APPS`` setting. The order is not important::

    INSTALLED_APPS = (
        ...
        "nens_auth_client",
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",
        ...
    )

Also, add the following setting to be able to connect remote users to the local
Django user database::

    AUTHENTICATION_BACKENDS = [
        "nens_auth_client.backends.RemoteUserBackend",       
        "nens_auth_client.backends.SSOMigrationBackend",  # only for apps with existing users (see below)
        "django.contrib.auth.backends.ModelBackend",  # only if you still need local login (e.g. admin)
    ]

Identify the authorization server (the "issuer")::

    NENS_AUTH_ISSUER = "https://cognito-idp.eu-west-1.amazonaws.com/...."


Usage: login/logout views
-------------------------

Some settings that identify your application as an OpenID Connect Client::

    NENS_AUTH_CLIENT_ID = "..."  # generate one on AWS Cognito
    NENS_AUTH_CLIENT_SECRET = "..."  # generate one on AWS Cognito
 
Include the ``nens-auth-client`` urls in your application's urls.py::

    from django.conf.urls import include

    urlpatterns = [
        ...
        url(r"^accounts/", include("nens_auth_client.urls", namespace="auth")),
        ...
    ]

You must register the absolute ``authorize`` and ``logout`` URIs in AWS Cognito.
If the site runs on multiple domains, they all have to be registered. Wildcards
are not possible because of security reasons.

Optionally set defaults for the redirect after successful login/logout::

    NENS_AUTH_DEFAULT_SUCCESS_URL = "/welcome/"
    NENS_AUTH_DEFAULT_LOGOUT_URL = "/goodbye/"


Usage: invites and user creation
--------------------------------

If a user logs in for the first time, it is only accepted if the user has a
valid invite id. So: new users may be created exclusively through Invites. This
is because there is no way to safely match local users to remote users.

The exception to this rule is the ``SSOMigrationBackend``. If users came
from our old SSO, they can be matched by username.

After the user logs in successfully, a RemoteUser object is created to handle
subsequent logins.

Additionally, an invite contains ``permissions`` to be assigned to the new user.
Permissions are assigned through a ``PermissionBackend``, that differs per app,
because each app has its own authorization model. This project has an
example implementation in ``permissions.py``. This is the default backend::

    NENS_AUTH_PERMISSION_BACKEND = "nens_auth_client.permissions.DjangoPermissionBackend"

The default `DjangoPermissionBackend` expects natural keys of django's builtin
``Permission`` objects like this::

    {"user_permissions":  [["add_invite", "nens_auth_client", "invite"]]}


Usage: bearer tokens
--------------------

If your web application acts as a Resource Server in the Authorization Code
or Client Credentials Flow, then it will need to accept Bearer tokens in
http requests. ``nens-auth-client`` has a middleware for this::

    MIDDLEWARE = (
        ...
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "nens_auth_client.middleware.AccessTokenMiddleware",
        ...
    )

This middleware will set the ``request.user.oauth2_scope`` that your
application may use for additional authorization logic.

Also, set the ``NENS_AUTH_RESOURCE_SERVER_ID``, which
should match the one set in the AWS Cognito. It needs a trailing slash::

    NENS_AUTH_RESOURCE_SERVER_ID = "..."  # configure this on AWS Cognito

Note that the external user ID (``"sub"`` claim) must already be registered in
the app (as a ``RemoteUser``). There is not much you can do about that because
bearer tokens typically do not include much information about the user. A user
should do a one-time login so that a ``RemoteUser`` is created. After that,
the user can be found by the "sub" claim in the access token.

For the Client Credentials Flow there isn't any user. For that, a RemoteUser
should be created manually (with ``external_user_id`` equaling the client_id.
This should be attached to some service account.


Error handling
--------------

The ``authorize`` view may give several kinds of exceptions. See the relevant
docstring. These errors are unhandled by nens_auth_client, so that django's
built-in 403 or 500 templates are used.

For overriding these views, see: https://docs.djangoproject.com/en/3.1/ref/views/#error-views


Local development
-----------------

(Re)create & activate a virtualenv::

    $ rm -rf .venv
    $ virtualenv .venv --python=python3
    $ source .venv/bin/activate

Install package and run tests::

    (virtualenv)$ pip install django==2.2
    (virtualenv)$ pip install -e .[test]
    (virtualenv)$ pytest

For testing against an actual User Pool, configure the following environment
variables (for instance in an ``.env`` file)::

    NENS_AUTH_CLIENT_ID=...
    NENS_AUTH_CLIENT_SECRET=...
    NENS_AUTH_ISSUER=https://cognito-idp.{region}.amazonaws.com/{pool-id}

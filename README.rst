nens-auth-client
==========================================

Introduction
------------

This library defines the necessary views and models to connect the AWS Cognito
user pool to the local django user database.

Required settings
-----------------

The nens-auth-client library exposes one django application: ``nens_auth_client``.
The django built-in apps ``auth``, ``sessions`` and ``contenttypes`` are
also required, but they probably are already there.
Add these to the ``INSTALLED_APPS`` setting. Make sure your project's app is
listed *before* nens_auth_client::

    INSTALLED_APPS = [
        ...
        "nens_auth_client",
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",
        ...
    ]

Modify the authentication backends as follows::

    AUTHENTICATION_BACKENDS = [
        "nens_auth_client.backends.RemoteUserBackend",
        "nens_auth_client.backends.SSOMigrationBackend",
	# ^^^ only for apps with existing users (see below)
        "django.contrib.auth.backends.ModelBackend",
	# ^^^ only if you still need local login (e.g. admin)
    ]

Set the authorization server (the "issuer")::

    NENS_AUTH_ISSUER = "https://cognito-idp.eu-west-1.amazonaws.com/...."

Identify your application as a unique OpenID Connect Client::

    NENS_AUTH_CLIENT_ID = "..."  # generate one on AWS Cognito
    NENS_AUTH_CLIENT_SECRET = "..."  # generate one on AWS Cognito

Include the ``nens-auth-client`` urls in your application's urls.py::

    from django.conf.urls import include

    urlpatterns = [
        ...
        url(r"^accounts/", include("nens_auth_client.urls", namespace="auth")),
        ...
    ]

You must register the absolute ``authorize`` and ``logout-success`` URIs in
AWS Cognito.
If the site runs on multiple domains, they all have to be registered. Wildcards
are not possible because of security reasons.

The admin and djangorestframework login / logout views should be overridden.
Otherwise these views still try to authenticate in the local (Django) database.
Achieve this as follows (in urls.py)::

    from nens_auth_client.urls import override_admin_auth
    from nens_auth_client.urls import override_rest_framework_auth

    urlpatterns = [
        ...
        *override_admin_auth(),
        url(r"^admin/", admin.site.urls),  # is probably already there
        ...
        *override_rest_framework_auth(),  # only if you use rest_framework
        url(r"^api-auth/", include("rest_framework.urls"), namespace="rest_framework"),
        ...
    ]

The override always goes before the corresponding include.
Note that if you use a non-standard path it should be given as argument to
the override, e.g. ``override_admin_auth("my-custom-admin-path")``.
The path admin/local-login is added (by the override) for emergency access.

If not done already for your project, set up a working email backend and a
sender ('from') email address::

    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
    EMAIL_HOST = ...
    DEFAULT_FROM_EMAIL = ...

See https://docs.djangoproject.com/en/2.2/topics/email/ for further information.


Login & logout
--------------

The login flow follows the OpenID Connect flow. A summary:

1. The user accesses the "login" view (optionally with a ``next`` query parameter).
2. The user is redirected to the Authorization Server (AWS Cognito).
3. The user logs in on the Authorization server.
4. The user is redirected to the "authorize" view with an authorization code.
5. The "authorize" view contains code to exchange the code for an ID Token (at the Authorization Server).
6. The ID token contains a "sub" (subject) claim, which is a unique identifier of the user.
   A RemoteUser is looked up with a matching "external_user_id". The associated
   Django user is logged in. If the user does not exist, the server responds with a
   403 Permission Denied, unless an invitation was included in step 1. (see First-time login section)
7. The User's metadata (email, first_name, last_name) is updated from the claims in the ID token.
8. The user is redirected to the 'next' URL provided in step 1.

The logout flow follows a similar flow:

1. The user accesses the "logout" view (optionally with a ``next`` query parameter).
2. The user is logged out locally and is redirected to the Authorization Server's logout view.
3. The Authorization Server logs the user out.
4. The user is redirected to the "logout-success" view.
5. The user is redirected to the 'next' URL provided in step 1.

Optionally set defaults for the redirects after successful login/logout::

    NENS_AUTH_DEFAULT_SUCCESS_URL = "/welcome/"
    NENS_AUTH_DEFAULT_LOGOUT_URL = "/goodbye/"


First-time logins
-----------------

For first-time logins, there is no RemoteUser object to match the external
user ID with a local django user. In this case, users are accepted only if the
user presents a valid invitation. This is because there is no way to safely
match external user ids to local django users.

There are two kinds of invitations: invitations with user, and invitations
without. If the invitation has a user set, the external user id will be
connected to that user (through a RemoteUser). If the invitation has no user
set, a new User + RemoteUser will be created. The local username will equal the
Cognito username field (``"cognito:username"``).

Additionally, an invitation contains ``permissions`` to be assigned to the user.
Permissions are assigned through a ``PermissionBackend``, that differs per app,
because each app has its own authorization model. This project has an
example implementation in ``permissions.py``. This is the default backend::

    NENS_AUTH_PERMISSION_BACKEND = "nens_auth_client.permissions.DjangoPermissionBackend"

The default `DjangoPermissionBackend` expects natural keys of django's builtin
``Permission`` objects like this::

    {"user_permissions":  [["add_invite", "nens_auth_client", "invite"]]}

Invitations can be accepted by users through the ``accept_invitation`` url,
which looks like this::

    /accept_invitation/{secret invitation slug}/accept/?next=/admin/

If the user is logged in, the invitation is accepted and the user is redirected
to (in this example) `/admin/`. If not, the user is first redirected to the
login view (adding the `invitation` query parameter to do the first-time login).

The complete first-time user flow goes like this:

1. https://my.site/invitations/abc123/accept/?next=/admin/
2. https://my.site/login/?invitation=abc123&next=%2Finvitations%2Fabc123%2Faccept%2F%3Fnext%3D%2Fadmin%2F
3. https://aws.cognito/login?...&redirect_uri=https://auth.lizard.net/authorize/
4. https://my.site/authorize/
5. https://my.site/invitations/abc123/accept/?next=/admin/
6. https://my.site/admin/


Creating and sending invitations
--------------------------------

Invitation objects can be created with and without an associated user. For
invitations that have no associated user, a user will be created
automatically when the invite is accepted.

Creation via the admin:

1. Create an invitation. The "email" field is mandatory. Optionally
   provide "user", "permissions" and "created_by". The form of "permissions"
   depends on the permission backend. Note that the "email" is independent from
   the "user.email".
2. Select the newly created invitation and use "(Re)send selected invitations"
   in the dropdown at the top. This will send the invitation email.
   Another option is to copy the ``accept_url`` and supply that to the
   invited user by other means.

Programmatic creation:

1. Create an Invitation object using ``Invitation.objects.create``.
2. Send the email using ``invitation.send_email``, or build your own logic
   using ``invitation.get_accept_url(request)`` to get the accept URL.

The invitation email can be changed by overriding the ``nens_auth_client/invitation.txt``
and ``nens_auth_client/invitation.html`` templates. For this, your project's app
needs to be listed *before* nens_auth_client in the ``INSTALLED_APPS``.
The default email subject is ``"Invitation"`` is the default subject.
Change the invitation email subject as follows::

    NENS_AUTH_INVITATION_EMAIL_SUBJECT = "My-custom-subject"  # this is the default

By default, an invitation is valid for 14 days. Change this as follows::

    NENS_AUTH_INVITATION_EXPIRY_DAYS = 7


Cleaning invitations
--------------------

Invitation objects need to be cleaned periodically, or else the database table
will keep growing. Use the management command `clean_invitations` for that, or
wrap the `nens_auth_client.models.clean_invitations` function in a celery task
and schedule it every day.


Migrating existing users
------------------------

For apps with an existing user database, it may not be desirable to have every
user going through the invitation process (described above). For this we have the
``SSOMigrationBackend``. If the user's ID Token has ``"custom:from_sso": "1"``,
users are matched by username. On first-time login, a RemoteUser object is
created to link the external and local users permanently.


Bearer tokens (optional)
------------------------

If your web application acts as a Resource Server in the Authorization Code
or Client Credentials Flow, then it will need to accept Bearer tokens in
http requests. ``nens-auth-client`` implements two methods for this:
Django middleware and Django REST framework authentication class.

In both cases, you need to configure the ``NENS_AUTH_RESOURCE_SERVER_ID`` setting, which
should match the one set in the AWS Cognito. It needs a trailing slash::

    NENS_AUTH_RESOURCE_SERVER_ID = "..."  # configure this on AWS Cognito


*Option 1: middleware*

The Django Middleware will log the user in without starting a session. It works
for all views. Additionaly, middleware will set the ``request.user.oauth2_scope``
that your application may use for additional authorization logic.

Configure the middleware as follows::

    MIDDLEWARE = [
        ...
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "nens_auth_client.middleware.AccessTokenMiddleware",
        ...
    ]


*Option 2: REST framework authentication class*

The REST framework authentication class will is only applicable to REST framework
views. After a token appears valid, it will set ``request.user`` and
``request.auth.scope``. Permission classes should use the scope for additional
authorization logic. By default (like in the built-in ``IsAuthenticated``)
the scope is ignored, which may lead to more permissive behavior than expected.

Configure the authentication class::


    REST_FRAMEWORK = {
        (...)
        "DEFAULT_AUTHENTICATION_CLASSES": [
            "nens_auth_client.rest_framwork.OAuth2TokenAuthentication",
            (...)
        ]
    }

*Notes*

When using a Bearer token, the external user ID (``"sub"`` claim) must already be registered in
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
built-in 403, 404, and 500 templates are used.

For overriding these views, see: https://docs.djangoproject.com/en/3.1/ref/views/#error-views

The error detail messages can be modified with the following settings:

- NENS_AUTH_ERROR_USER_DOES_NOT_EXIST
- NENS_AUTH_ERROR_USER_INACTIVE
- NENS_AUTH_ERROR_INVITATION_DOES_NOT_EXIST
- NENS_AUTH_ERROR_INVITATION_UNUSABLE
- NENS_AUTH_ERROR_INVITATION_EXPIRED
- NENS_AUTH_ERROR_INVITATION_WRONG_USER (accepts ``actual_user`` and ``expected_user`` placeholders)
- NENS_AUTH_ERROR_INVITATION_WRONG_EMAIL (accepts ``actual_email`` and ``expected_email`` placeholders)


Local development
-----------------

(Re)create & activate a virtualenv::

    $ rm -rf .venv
    $ virtualenv .venv --python=python3
    $ source .venv/bin/activate

Install package and run tests::

    (virtualenv)$ pip install django==3.2
    (virtualenv)$ pip install -e .[test]
    (virtualenv)$ pytest

For testing against an actual User Pool, configure the following environment
variables (for instance in an ``.env`` file)::

    NENS_AUTH_CLIENT_ID=...
    NENS_AUTH_CLIENT_SECRET=...
    NENS_AUTH_ISSUER=https://cognito-idp.{region}.amazonaws.com/{pool-id}

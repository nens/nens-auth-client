nens-auth-client
==========================================

Introduction
------------

This library defines the necessary views and models to connect the AWS Cognito
user pool to the local django user database.

Usage
-----

The nens-auth-client library exposes one django application: ``nens_auth_client``.
The django built-in apps ``auth``, ``sessions`` and ``contenttypes`` are
also required, but they probably are already there.
Add these to the ``INSTALLED_APPS`` setting:

.. code-block:: python
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
        "django.contrib.auth.backends.ModelBackend",
        "nens_auth_client.backends.SocialUserBackend",
        "nens_auth_client.backends.EmailVerifiedBackend",
    ]

Some settings that identify your application and set up the authorization server::

    NENS_AUTH_CLIENT_ID = "..."  # generate one on AWS Cognito
    NENS_AUTH_CLIENT_SECRET = "..."  # generate one on AWS Cognito
    NENS_AUTH_ACCESS_TOKEN_URL = "https://nens.auth.eu-west-1.amazoncognito.com/oauth2/token"
    NENS_AUTH_AUTHORIZE_URL = "https://nens.auth.eu-west-1.amazoncognito.com/oauth2/authorize"
    NENS_AUTH_ISSUER = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_9AyLE4ffV"
    NENS_AUTH_JWKS_URI = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_9AyLE4ffV/.well-known/jwks.json"


Finally, include the ``nens-auth-client`` urls to your application's urls.py::

    from django.conf.urls import include

    urlpatterns = [
        ...
        url(r"^accounts/", include("nens_auth_client.urls", namespace="auth")),
        ...
    ]

You must register the absolute ``authorize`` and ``logout`` URIs in AWS Cognito.
If the site runs on multiple domains, they all have to be registered. Wildcards
are not possible because of security reasons.


User association logic
----------------------

The OpenID Connect flow provides an ID token to your client application. What
to do with that, is entirely up to the application. We like to use the built-in
django User models. To associate the externally provided user-id with a local
user, the django ``AUTHENTICATION_BACKENDS`` are used.
See the `django docs <https://docs.djangoproject.com/en/2.2/topics/auth/customizing/#customizing-authentication-in-django>`_.

In the nens-auth-client ``authorize`` view, the ``authenticate`` function from
django.contrib.auth is called with a keyword argument ``userinfo``. This
``userinfo`` equals the decoded ID token. It is up to the authentication
backends to return a ``user`` instance based on ``userinfo``.

In the default implementation nens-auth-client associates external users to
remote users via the ``RemoteUser`` model. If there is no existing association,
a user is selected by email address (if it is verified). This logic is contained
in the ``AUTHENTICATION_BACKENDS`` setting:

- ``RemoteUserBackend`` produces a user if there is a RemoteUser present with
  its ``external_user_id`` matching ``userinfo["sub"]``
- ``EmailVerifiedBackend`` produces a user if there is one with an matching
  ``userinfo["email"]`` and if ``userinfo["email_verified"]`` is True.

At the end of the authentication chain, a ``RemoteUser`` object is created for
next time usage. This is skipped when the user was authenticated via the
``RemoteUserBackend``. Control this feature with ``NENS_AUTH_AUTO_CREATE_SOCIAL_USER``.

If you application requires this logic to be appended, start with subclassing
``django.contrib.auth.backends.ModelBackend`` and overriding the ``authenticate``
method with call signature ``(request: Request, userinfo: dict)``.


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

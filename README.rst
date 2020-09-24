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

Also, add the following setting to override the default Django authentication
backend:

.. code-block:: python
    AUTHENTICATION_BACKENDS = [
        "nens_auth_client.backends.SocialUserBackend",
        "nens_auth_client.backends.EmailVerifiedBackend",
    ]

Some settings that identify your application and set up the authorization server:

.. code-block:: python
    NENS_AUTH_CLIENT_ID = "..."  # generate one on AWS Cognito
    NENS_AUTH_CLIENT_SECRET = "..."  # generate one on AWS Cognito
    NENS_AUTH_REDIRECT_URI = "https://<your-app-domain>/authorize"  # configure this also on AWS Cognito
    NENS_AUTH_ACCESS_TOKEN_URL = "https://nens.auth.eu-west-1.amazoncognito.com/oauth2/token"
    NENS_AUTH_AUTHORIZE_URL = "https://nens.auth.eu-west-1.amazoncognito.com/oauth2/authorize"
    NENS_AUTH_ISSUER = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_9AyLE4ffV"
    NENS_AUTH_JWKS_URI = "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_9AyLE4ffV/.well-known/jwks.json"


Finally, include the ``nens-auth-client`` urls to your application's urls.py:

.. code-block:: python
    from django.conf.urls import include

    urlpatterns = [
        ...
        url(r"^accounts/", include("nens_auth_client.urls", namespace="auth")),
        ...
    ]


User association logic
----------------------

The OpenID Connect flow provides an ID token to your client application. What
to do with that, is entirely up to the application. We like to use the built-in
django User models. To associate the externally provided user-id with a local
user, the django ``AUTHENTICATION_BACKENDS`` are used.
See the [django docs](https://docs.djangoproject.com/en/2.2/topics/auth/customizing/#customizing-authentication-in-django).

In the nens-auth-client ``authorize`` view, the ``authenticate`` function from
django.contrib.auth is called with a keyword argument ``verified_id_token``. It
is up to the authentication backends to return a ``user`` instance.

In the default implementation, nens-auth-client associates external users to
remote users by emailaddress (if it is verified). The association between an
external and local user is saved via the creation of a ``SocialUser`` object.

 - ``SocialUserBackend`` produces a user if there is a SocialUser present with
   its ``external_user_id`` matching ``verified_id_token["sub"]``
 - ``EmailVerifiedBackend`` produces a user if there is one with an matching
   email address and if the externally provided email is verified.

At the end of the authentication chain, a SocialUser object may be created for
next time usage. This is controlled with the setting ``AUTO_CREATE_SOCIAL_USER``.


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

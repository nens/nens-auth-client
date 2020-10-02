Changelog of nens-auth-client
===================================================


0.2 (unreleased)
----------------

- Removed the NENS_AUTH_REDIRECT_URI and NENS_AUTH_LOGOUT_REDIRECT_URI. Instead
  generate them from the authorize and logout view paths, respectively. Note
  that requires all possible site domains to be registered with the
  Authorization Server.

- Django 1.11 compatibilty in urls.py.

- Set Cache-Control headers to "no-store" for login, authorize and logout.

- Added AccessTokenMiddleware enabling usage of this package in Resource
  Servers.

- Renamed "userinfo" to "claims" in the authentication backends.


0.1 (2020-09-29)
----------------

- Initial project structure created with cookiecutter and
  https://github.com/nens/cookiecutter-djangosite-template

- Added RemoteUser model.

- Added login, authorize and logout views for login/logout via OpenID Connect
  (AWS Cognito). Default settings are setup via django-appconf.

- Added unittests for login and authorize views.

- Added NENS_AUTH_ISSUER setting.

- Parsing the next query parameter in the login view. If it is unsafe or not
  provider, use ``NENS_AUTH_DEFAULT_SUCCESS_URL``.

- If already logged in, the login view redirects to the success_url directly.

- Added custom authentication backends "RemoteUserBackend" and
  "EmailVerifiedBackend" to associate remote user ids with local users.

- Call AWS LOGOUT endpoint in the logout view and added logout redirects.

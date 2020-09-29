Changelog of nens-auth-client
===================================================


0.1 (unreleased)
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

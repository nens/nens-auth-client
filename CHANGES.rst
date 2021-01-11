Changelog of nens-auth-client
===================================================


0.6 (unreleased)
----------------

- Made all 403 error messages configurable. Some errors from the accept_invitation
  view are now a 403 instead of a 404.

- Added an invitation_accepted signal.

- Store tokens on the RemoteUser object and display them in the admin.

- Extend SSOMigrationBackend so that it matches external users by username
  (from email) if it is a Google account ending with @nelen-schuurmans.nl.


0.5 (2020-12-10)
----------------

- Fixed error when using authorize view with "invitation" query parameter.


0.4 (2020-12-08)
----------------

- Added Invitation model.

- The authorize view accepts an "invitation" query parameter. If the invitation
  is valid, a new user will be created. Or, if present, invitation.user will
  be used to log in.

- Added accept_invitation view.

- Added invitation expiry and a management command "clean_invitations".

- Removed the EmailVerifiedBackend.

- Added SSOMigrationBackend.

- Removed all secrets from the repository to be able to make it public.


0.3 (2020-10-20)
----------------

- Fix reverse() usage when urls are used in a namespace in another app.


0.2 (2020-10-16)
----------------

- Removed the NENS_AUTH_REDIRECT_URI and NENS_AUTH_LOGOUT_REDIRECT_URI. Instead
  we generate them from the authorize and logout view paths, respectively. Note
  that it requires all possible site domains to be registered with the
  Authorization Server.

- Django 1.11 compatibilty in urls.py.

- Set Cache-Control headers to "no-store" for login, authorize and logout.

- Added AccessTokenMiddleware enabling usage of this package in Resource
  Servers.

- Renamed "userinfo" to "claims" in the authentication backends.

- Error query parameters are handled in the authorize endpoint.

- NENS_AUTH_TIMEOUT is used in the token requests.

- Fix: inactive users can no longer log in.


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

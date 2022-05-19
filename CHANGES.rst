Changelog of nens-auth-client
===================================================


1.1 (unreleased)
----------------

- Added ``AcceptNensBackend`` for automatically accepting N&S users without
  prior invitation. Handy for some internal websites.

- Solved ``@Nelen-Schuurmans.nl`` capitalization issue.


1.0 (2022-04-04)
----------------

- Do not raise an internal server error when users click 'backwards' or 'forwards' in
  the browser. Instead, restart the login process by redirecting to the login view.

- Fixed authlib 1.* compatibility.


0.14 (2022-03-14)
-----------------

- Added OAuth2TokenAuthentication as an alternative to the AccessTokenMiddleware when
  using django REST framework.


0.13 (2022-03-01)
-----------------

- Added requests_session.OAuth2Session to get a requests Session with an access token.
  If the access token expires the token is refreshed.

- Added requests_session.OAuth2CCSession for fetching an access token in the
  Client Credentials Grant.

- Fixed library with Django 4.*.

- Fixed unittests with authlib 0.15.5.


0.12 (2021-09-30)
-----------------

- Adapted code to match "NelenSchuurmans" as trusted provider name. It turned
  out that "Nelen&Schuurmans" had issues: the ampersand was not encoded in
  URLs being passed.

- Previously, local Nelen & Schuurmans users were automatically associated
  with their remote Google account. This now works for Azure AD accounts
  too, even if a Google association already exists.


0.11 (2021-09-21)
-----------------

- Extend SSOMigrationBackend so that it matches external users by username
  (from email) if it is an Azure AD account ending with @nelen-schuurmans.nl.

- Dropped support for Python 3.5. Added Python 3.9 to the versions to be
  tested.


0.10 (2021-02-23)
-----------------

- SSOMigrationBackend now matches usernames case-insensitively.


0.9 (2021-01-27)
----------------

- Fixed bug in AccessTokenMiddleware.


0.8 (2021-01-21)
----------------

- Pick the email as username for newly registered users coming from an external
  identity provider.

- Handle username uniqueness constraint by appending 4 random characters after
  the username when necessary.

- Added a check if the user's and invitation's email match. It does not matter
  whether the user's email was verified.

- Split the logout view in two. It is not used anymore as the callback url
  after remote logout: for that /logout-success/ is introduced. This so that
  users can always logout, also when local login failed.

- Added a logout and then login functionality. This can be used by calling
  /login?force_logout=true.

- Never require presence of "email" claim in the ID token.


0.7 (2021-01-13)
----------------

- Fixed faulty error message if user does not exist.

- Fixed authorize if there is no redirect in the session.

- Stop storing the default redirect urls in the session. This prevents creating
  a session in the login or logout flows if no 'next' url param is used.


0.6 (2021-01-11)
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

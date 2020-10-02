from django.conf import settings


def preprocess_access_token(claims):
    """Convert AWS Cognito Access token claims to standard form, inplace.

    This function is intended for usage in the NENS_AUTH_PREPROCESS_ACCESS_TOKEN
    setting.

    AWS Cognito Access tokens are missing the "aud" (audience) claim and
    instead put the audience into each scope.

    This function filters the scopes on those that start with the
    NENS_AUTH_RESOURCE_SERVER_ID setting. If there is any matching scope, the
    "aud" claim will be set.

    The resulting "scope" has no audience(s) in it anymore.

    Args:
      claims (dict): payload of the Access Token

    Example:
    >>> audience = "https://some/api/"
    >>> claims = {
        "scope": "https://some/api/users.readwrite https://something/else"
    }
    >>> preprocess_access_token(claims)
    >>> claims
    {
        "aud": "https://some/api/",
        "scopes": "users.readwrite",
        ...
    }
    """
    # Do nothing if there is an already an "aud" claim
    if "aud" in claims:
        return

    # Get the expected "aud" claim
    audience = settings.NENS_AUTH_RESOURCE_SERVER_ID

    # List scopes and chop off the audience from the scope
    new_scopes = []
    for scope_item in claims.get("scope", "").split(" "):
        if scope_item.startswith(audience):
            scope_without_audience = scope_item[len(audience):]
            new_scopes.append(scope_without_audience)

    # Don't set the audience if there are no scopes as Access Token is
    # apparently not meant for this server.
    if not new_scopes:
        return

    # Update the claims inplace
    claims["aud"] = audience
    claims["scope"] = " ".join(new_scopes)


def get_logout_endpoint(server_metadata):
    """Create the LOGOUT endpoint from the server metadata dictionary"""
    authorization_endpoint = server_metadata['authorization_endpoint']
    return authorization_endpoint.replace("/oauth2/authorize", "/logout")

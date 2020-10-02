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
    # Get the expected "aud" claim
    audience = settings.NENS_AUTH_RESOURCE_SERVER_ID
    assert audience[-1] == "/"

    # Stop if there is an existing "aud" claim and it does not match
    if "aud" in claims and claims["aud"] != audience:
        return

    # List scopes and chop off the audience from the scope
    new_scopes = []
    for scope in claims.get("scope", "").split(" "):
        if scope.startswith(audience):
            new_scopes.append(scope[len(audience):])

    # Don't set the audience if there are no scopes as Access Token is
    # apparently not meant for this server.
    if not new_scopes:
        return

    # Update the claims inplace
    claims["aud"] = audience
    claims["scope"] = " ".join(new_scopes)

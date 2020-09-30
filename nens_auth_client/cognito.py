from django.conf import settings


def preprocess_access_token(claims):
    """Convert AWS Cognito Access token claims to RFC7523 compliant form.

    AWS Cognito Access tokens are missing the "aud" (audience) claim and
    instead put the audience into each scope.

    This function filters the scopes on those that start with the
    NENS_AUTH_RESOURCE_SERVER_ID setting. If there is any matching scope, the
    "aud" claim will be set.

    The resulting "scope" has no audience(s) in it anymore.

    Args:
      claims (dict): payload of the Access Token
      audience (str): URL of this Resource Server (with trailing slash)

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
    aud = settings.NENS_AUTH_RESOURCE_SERVER_ID
    assert aud[-1] == "/"
    new_scopes = []
    for scope in claims.get("scope", "").split(" "):
        if scope.startswith(aud):
            new_scopes.append(scope[len(aud) :])
    if not new_scopes:
        return  # Don't set the audience if there are no relevant scopes
    claims["aud"] = aud
    claims["scope"] = " ".join(new_scopes)

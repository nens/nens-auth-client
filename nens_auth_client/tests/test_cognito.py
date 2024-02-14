from nens_auth_client.cognito import CognitoOAuthClient
from nens_auth_client.cognito import preprocess_access_token

import pytest


@pytest.mark.parametrize(
    "claims,expected",
    [
        ({"scope": "api/read"}, {"aud": "api/", "scope": "read"}),
        ({"scope": "api/r api/w"}, {"aud": "api/", "scope": "r w"}),
        ({"scope": "api/read write"}, {"aud": "api/", "scope": "read"}),
        ({"scope": "api/read other/write"}, {"aud": "api/", "scope": "read"}),
        ({"scope": "read"}, {"scope": "read"}),
        ({"scope": "http://a/read"}, {"scope": "http://a/read"}),
        ({"aud": "api/", "scope": "api/r"}, {"aud": "api/", "scope": "api/r"}),
        ({"aud": "a/", "scope": "a/read"}, {"aud": "a/", "scope": "a/read"}),
    ],
)
def test_preprocess_access_token(claims, expected, settings):
    settings.NENS_AUTH_RESOURCE_SERVER_ID = "api/"
    preprocess_access_token(claims)
    assert claims == expected


def test_extract_provider_name_present():
    # Extract provider name when it is present.
    claims = {"identities": [{"providerName": "Google"}]}
    assert CognitoOAuthClient.extract_provider_name(None, claims) == "Google"


def test_extract_provider_name_absent():
    # Return None when a provider name cannot be found.
    claims = {"some": "claim"}
    assert CognitoOAuthClient._extract_provider_name(None, claims)

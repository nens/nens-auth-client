from nens_auth_client.cognito import preprocess_access_token
import pytest


@pytest.mark.parametrize("claims,expected", [
    ({"scope": "api/read"}, {"aud": "api/", "scope": "read"}),
    ({"scope": "api/r api/w"}, {"aud": "api/", "scope": "r w"}),
    ({"scope": "api/read write"}, {"aud": "api/", "scope": "read"}),
    ({"scope": "read"}, {"scope": "read"}),
    ({"scope": "http://a/read"}, {"scope": "http://a/read"}),
    ({"aud": "api/", "scope": "read"}, {"aud": "api/", "scope": "read"}),
    ({"aud": "api/", "scope": "api/read"}, {"aud": "api/", "scope": "read"}),
    ({"aud": "a/", "scope": "read"}, {"aud": "a/", "scope": "read"}),
    ({"aud": "a/", "scope": "api/read"}, {"aud": "a/", "scope": "api/read"}),
])
def test_preprocess_access_token(claims, expected, settings):
    settings.NENS_AUTH_RESOURCE_SERVER_ID = "api/"
    preprocess_access_token(claims)
    assert claims == expected

from nens_auth_client.wso2 import WSO2AuthClient

import pytest


def test_extract_provider_name():
    # Extract provider name when it is present.
    claims = {"sub": "abc123"}
    assert WSO2AuthClient.extract_provider_name(claims) is None


@pytest.mark.parametrize(
    "claims,expected",
    [
        ({"email": "a@b.com"}, "a@b.com"),
    ],
)
def test_extract_username(claims, expected):
    assert WSO2AuthClient.extract_username(claims) == expected


def test_parse_access_token_includes_claims(access_token_generator):
    with pytest.raises(NotImplementedError) as e:
        WSO2AuthClient.parse_access_token(None, access_token_generator())

    # error is raised with claims as arg
    assert e.value.args[0]["client_id"] == "1234"

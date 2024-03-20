from authlib.jose.errors import JoseError
from authlib.oidc.discovery import get_well_known_url
from django.conf import settings
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


@pytest.fixture
def wso2_client():
    return WSO2AuthClient(
        "foo",
        server_metadata_url=get_well_known_url(
            settings.NENS_AUTH_ISSUER, external=True
        ),
    )


def test_parse_access_token_wso2(access_token_generator, jwks_request, wso2_client):
    # disable 'token_use' (not included in WSO2 access token)
    claims = wso2_client.parse_access_token(
        access_token_generator(email="test@wso2", token_use=None)
    )

    assert claims["email"] == "test@wso2"


@pytest.mark.parametrize(
    "claims_mod", [{"aud": "abc123"}, {"sub": None}, {"iss": "abc123"}, {"exp": 0}]
)
def test_parse_access_token_wso2_invalid_claims(
    claims_mod, access_token_generator, jwks_request, wso2_client
):
    token = access_token_generator(**claims_mod)
    with pytest.raises(JoseError):
        wso2_client.parse_access_token(token)

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

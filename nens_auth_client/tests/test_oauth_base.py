from authlib.jose.errors import JoseError
from authlib.oidc.discovery import get_well_known_url
from django.conf import settings
from nens_auth_client.oauth_base import BaseOAuthClient
from unittest import mock

import pytest
import time


@pytest.fixture
def oauth_client():
    return BaseOAuthClient(
        "foo",
        server_metadata_url=get_well_known_url(
            settings.NENS_AUTH_ISSUER, external=True
        ),
    )


def test_parse_access_token(access_token_generator, jwks_request, oauth_client):
    claims = oauth_client.parse_access_token(access_token_generator(email="test@wso2"))

    assert claims["email"] == "test@wso2"


@pytest.mark.parametrize(
    "claims_mod", [{"aud": "abc123"}, {"sub": None}, {"iss": "abc123"}, {"exp": 0}]
)
def test_parse_access_token_invalid_claims(
    claims_mod, access_token_generator, jwks_request, oauth_client
):
    token = access_token_generator(**claims_mod)
    with pytest.raises(JoseError):
        oauth_client.parse_access_token(token)


def test_parse_access_token_preprocess(
    access_token_generator, jwks_request, oauth_client
):
    # In this example, the preprocess function makes an otherwise invalid token valid
    def preprocess(claims):
        claims["exp"] = time.time() + 1

    with mock.patch.object(
        oauth_client, "preprocess_access_token", side_effect=preprocess
    ):
        claims = oauth_client.parse_access_token(access_token_generator(exp=0))

    assert claims["exp"] > 0


def test_parse_access_token_preprocess_err(
    access_token_generator, jwks_request, oauth_client
):
    # In this example, the preprocess function makes an otherwise valid token invalid
    def preprocess(claims):
        claims["exp"] = 0

    with mock.patch.object(
        oauth_client, "preprocess_access_token", side_effect=preprocess
    ):
        with pytest.raises(JoseError):
            oauth_client.parse_access_token(access_token_generator())

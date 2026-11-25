from importlib.metadata import version
from joserfc.errors import InvalidKeyIdError
from joserfc.errors import JoseError
from nens_auth_client import oauth
from nens_auth_client.oauth import get_oauth_client
from packaging.version import Version

import pytest
import time


def test_openid_configuration_uri_can_be_configured(settings, mocker):
    settings.NENS_AUTH_OPENID_CONFIGURATION_URI = (
        "https://auth.example/.well-known/openid-configuration"
    )
    oauth.oauth_registry._clients.clear()
    oauth.oauth_registry._registry.clear()
    mocker.patch.object(oauth.oauth_registry, "create_client", side_effect=[None, "client"])
    register = mocker.patch.object(oauth.oauth_registry, "register")

    assert get_oauth_client() == "client"
    assert register.call_args.kwargs["server_metadata_url"] == (
        "https://auth.example/.well-known/openid-configuration"
    )


def test_parse_token_wrong_issuer(access_token_generator, jwks_request):
    token = access_token_generator(iss="https://google.com")
    with pytest.raises(JoseError):
        get_oauth_client().parse_access_token(token)


def test_parse_token_wrong_aud(access_token_generator, jwks_request):
    token = access_token_generator(aud="https://my/api/")
    with pytest.raises(JoseError):
        get_oauth_client().parse_access_token(token)


def test_parse_token_with_direct_audience(
    access_token_generator, jwks_request, settings
):
    settings.NENS_AUTH_RESOURCE_SERVER_ID = None
    settings.NENS_AUTH_AUDIENCE = "keycloak-client"
    token = access_token_generator(aud="keycloak-client")

    claims = get_oauth_client().parse_access_token(token)

    assert claims["aud"] == "keycloak-client"
    assert claims["scope"] == "readwrite"


def test_parse_token_expired(access_token_generator, jwks_request):
    # Note that authlib has a 120 seconds "leeway" (for clock skew)
    token = access_token_generator(exp=int(time.time()) - 121)
    with pytest.raises(JoseError):
        get_oauth_client().parse_access_token(token)


def test_parse_token_corrupt_signature(access_token_generator, jwks_request):
    token = access_token_generator()[:-1]
    with pytest.raises(JoseError):
        get_oauth_client().parse_access_token(token)


def test_parse_token_bad_signature(access_token_generator, jwks_request):
    token = access_token_generator()[:-16]
    with pytest.raises(JoseError):
        get_oauth_client().parse_access_token(token)


@pytest.mark.skipif(
    Version(version("authlib")) > Version("1.6.6"),
    reason="none algorithm is deprecated",
)
def test_parse_token_unsigned_token(access_token_generator, jwks_request):
    token = access_token_generator(alg="none")
    with pytest.raises(JoseError):
        get_oauth_client().parse_access_token(token)


def test_parse_token_invalid_key_id(access_token_generator, jwks_request):
    token = access_token_generator(kid="unknown_key_id")
    with pytest.raises(InvalidKeyIdError):
        get_oauth_client().parse_access_token(token)

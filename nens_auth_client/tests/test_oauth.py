from nens_auth_client.oauth import get_oauth_client
from authlib.jose.errors import JoseError
import time
import pytest


def test_decode_token_wrong_issuer(access_token_generator, jwks_request):
    token = access_token_generator(iss="https://google.com")
    with pytest.raises(JoseError):
        get_oauth_client().parse_bearer_token(token)


def test_decode_token_wrong_aud(access_token_generator, jwks_request):
    token = access_token_generator(aud="https://my/api/")
    with pytest.raises(JoseError):
        get_oauth_client().parse_bearer_token(token)


def test_decode_token_expired(access_token_generator, jwks_request):
    # Note that authlib has a 120 seconds "leeway" (for clock skew)
    token = access_token_generator(exp=int(time.time()) - 121)
    with pytest.raises(JoseError):
        get_oauth_client().parse_bearer_token(token)


def test_decode_token_corrupt_signature(access_token_generator, jwks_request):
    token = access_token_generator()[:-1]
    with pytest.raises(JoseError):
        get_oauth_client().parse_bearer_token(token)


def test_decode_token_bad_signature(access_token_generator, jwks_request):
    token = access_token_generator()[:-16]
    with pytest.raises(JoseError):
        get_oauth_client().parse_bearer_token(token)


def test_decode_token_unsigned_token(access_token_generator, jwks_request):
    token = access_token_generator(alg="none")
    with pytest.raises(JoseError):
        get_oauth_client().parse_bearer_token(token)


def test_decode_token_invalid_key_id(access_token_generator, jwks_request):
    token = access_token_generator(kid="unknown_key_id")
    with pytest.raises(ValueError):
        get_oauth_client().parse_bearer_token(token)

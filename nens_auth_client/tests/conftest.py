import pytest
from authlib.jose import jwt
from django.conf import settings
import time
import requests_mock
import json
import os

DATA_PATH = os.path.join(os.path.dirname(__file__), "data")


@pytest.fixture(scope="module")
def private_key():
    # For testing purposes. Generated on mkjwk.org.
    with open(os.path.join(DATA_PATH, "testkey.json"), "r") as f:
        return json.load(f)


@pytest.fixture
def jwks(private_key):
    # The public part of the private_key (JWKS)
    fields_in_jwks = ["kty", "e", "use", "kid", "alg", "n"]
    return {"keys": [{x: private_key[x] for x in fields_in_jwks}]}


@pytest.fixture
def id_token_generator(private_key):
    """A function that generates a signed ID token"""

    def func(**extra_claims):
        header = {"alg": private_key["alg"], "kid": private_key["kid"]}
        key = private_key.copy()
        if "kid" in extra_claims:
            key["kid"] = extra_claims["kid"]
            header["kid"] = extra_claims.pop("kid")
        if "alg" in extra_claims:
            header["alg"] = extra_claims.pop("alg")
        template = {
            "iss": settings.NENS_AUTH_ISSUER,
            "aud": settings.NENS_AUTH_CLIENT_ID,
            "sub": "some_sub",
            "cognito:username": "some_username",
            "email": "some_email",
            "iat": int(time.time()),
            "exp": int(time.time()) + 10,
            "nonce": "nonce",
        }

        # sign the ID token with the private_key
        id_token = jwt.encode(header, {**template, **extra_claims}, key)
        return id_token.decode("ascii")  # convert bytes to string

    return func


@pytest.fixture
def rq_mocker():
    with requests_mock.Mocker() as m:
        yield m


@pytest.fixture
def auth_req_generator(rf, mocker, rq_mocker, jwks):
    """Mock necessary functions and create an authorization request"""

    def func(id_token, code="code", state="state", nonce="nonce"):
        # Mock the call to the external token API
        rq_mocker.post(settings.NENS_AUTH_ACCESS_TOKEN_URL, json={"id_token": id_token})
        # Mock the call to the external jwks
        rq_mocker.get(settings.NENS_AUTH_JWKS_URI, json=jwks)
        # Mock the user association logic (it needs db access)
        associate_user = mocker.patch("nens_auth_client.views.associate_user")
        associate_user.return_value = None

        # Create the request
        request = rf.get(f"/authorize?code={code}&state={state}")
        request.session = {
            "_cognito_authlib_state_": state,
            "_cognito_authlib_nonce_": nonce,
        }
        return request

    return func

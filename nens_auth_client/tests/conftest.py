from authlib.jose import jwt
from django.conf import settings
from django.contrib.auth import get_user_model
from nens_auth_client.views import LOGIN_REDIRECT_SESSION_KEY

import json
import os
import pytest
import requests_mock
import time

DATA_PATH = os.path.join(os.path.dirname(__file__), "data")
UserModel = get_user_model()


@pytest.fixture(scope="session")
def openid_configuration():
    # Returns an RFC-compliant response for OpenID Discovery
    host = "https://authserver"
    return {
        "authorization_endpoint": host + "/oauth2/authorize",
        "id_token_signing_alg_values_supported": ["RS256"],
        "issuer": settings.NENS_AUTH_ISSUER,
        "jwks_uri": settings.NENS_AUTH_ISSUER + "/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "scopes_supported": ["openid", "email", "profile"],
        "subject_types_supported": ["public"],
        "token_endpoint": host + "/oauth2/token",
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "userinfo_endpoint": host + "/oauth2/userInfo",
    }


@pytest.fixture(scope="session", autouse=True)
def mock_autodiscovery(openid_configuration):
    # We use real_http=False to block any outgoing HTTP request
    with requests_mock.Mocker(real_http=False) as m:
        m.get(
            settings.NENS_AUTH_ISSUER + "/.well-known/openid-configuration",
            json=openid_configuration,
        )
        yield


@pytest.fixture
def rq_mocker():
    # We use real_http=True because the request mocker is nested
    # inside "mock_autodiscovery"
    with requests_mock.Mocker(real_http=True) as m:
        yield m


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
def jwks_request(rq_mocker, jwks, openid_configuration):
    # Mock the call to the external jwks
    rq_mocker.get(openid_configuration["jwks_uri"], json=jwks)


@pytest.fixture
def token_generator(private_key):
    """A function that generates a signed token"""

    def func(**claims):
        """The "kid" and "alg" claims control the signature and do
        not end up as claims in the ID token.
        """
        # Create a copy of private_key and modify it with "alg" and "kid"
        key = private_key.copy()
        if "kid" in claims:
            key["kid"] = claims.pop("kid")
        if "alg" in claims:
            key["alg"] = claims.pop("alg")

        # The header should contain alg and kid:
        header = {"alg": key["alg"], "kid": key["kid"]}

        # Sign the token
        token = jwt.encode(header, claims, key)

        # Convert bytes to string
        return token.decode("ascii")

    return func


@pytest.fixture
def id_token_template():
    return {
        "iss": settings.NENS_AUTH_ISSUER,
        "aud": settings.NENS_AUTH_CLIENT_ID,
        "sub": "some_sub",
        "cognito:username": "some_username",
        "email": "some_email",
        "iat": int(time.time()),
        "exp": int(time.time()) + 10,
        "nonce": "nonce",
    }


@pytest.fixture
def id_token_generator(token_generator, id_token_template):
    """A function that generates a signed ID token"""

    def func(**extra_claims):
        claims = {**id_token_template, **extra_claims}
        return token_generator(**claims), claims

    return func


@pytest.fixture
def access_token_template():
    # For Authorization Code Flow (Resource Server side).
    return {
        "iss": settings.NENS_AUTH_ISSUER,
        "aud": settings.NENS_AUTH_RESOURCE_SERVER_ID,
        "scope": "readwrite",
        "token_use": "access",
        "sub": "some_sub",
        "username": "some_username",
        "iat": int(time.time()),
        "exp": int(time.time()) + 10,
        "jti": "abcd",
        "client_id": "1234",
    }


@pytest.fixture
def access_token_generator(token_generator, access_token_template):
    """A function that generates a signed access token"""

    def func(**extra_claims):
        claims = {**access_token_template, **extra_claims}
        claims = {k: v for (k, v) in claims.items() if v is not None}
        return token_generator(**claims)

    return func


@pytest.fixture
def auth_req_generator(
    rf, mocker, rq_mocker, jwks_request, settings, openid_configuration
):
    """Mock necessary functions and create an authorization request"""

    def func(id_token, user=None, code="code", state="state", nonce="nonce"):
        # Mock the call to the external token API
        rq_mocker.post(
            openid_configuration["token_endpoint"], json={"id_token": id_token}
        )
        # Mock the user association call
        authenticate = mocker.patch("nens_auth_client.views.django_auth.authenticate")
        authenticate.return_value = user
        # Disable automatic RemoteUser creation
        settings.NENS_AUTH_AUTO_CREATE_REMOTE_USER = False

        # Create the request
        request = rf.get(
            "http://testserver/authorize/?code={}&state={}".format(code, state)
        )
        request.session = {
            f"_state_oauth_{state}": {"data": {"nonce": nonce}},
            LOGIN_REDIRECT_SESSION_KEY: "http://testserver/success",
        }
        return request

    return func

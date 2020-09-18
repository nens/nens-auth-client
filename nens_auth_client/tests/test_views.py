import pytest
from urllib.parse import urlparse, parse_qs
from nens_auth_client import views
from authlib.integrations.base_client import MismatchingStateError
from authlib.jose.errors import JoseError
from django.conf import settings
import time


def test_login(rf):
    request = rf.get("/login")
    request.session = {}
    response = views.login(request)

    # login generated a redirect to the AUTHORIZE_URL
    assert response.status_code == 302
    url = urlparse(response.url)
    assert (
        f"{url.scheme}://{url.hostname}{url.path}" == settings.NENS_AUTH_AUTHORIZE_URL
    )

    # The query params are conform OpenID Connect spec
    # https://tools.ietf.org/html/rfc6749#section-4.1.1
    # https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    qs = parse_qs(url.query)
    assert qs["response_type"] == ["code"]
    assert qs["client_id"] == [settings.NENS_AUTH_CLIENT_ID]
    assert qs["redirect_uri"] == [settings.NENS_AUTH_REDIRECT_URI]
    assert qs["scope"] == [settings.NENS_AUTH_SCOPE]
    assert qs["state"] == [request.session["_cognito_authlib_state_"]]
    assert qs["nonce"] == [request.session["_cognito_authlib_nonce_"]]


def test_authorize(id_token_generator, auth_req_generator, rq_mocker):
    id_token = id_token_generator()
    request = auth_req_generator(id_token)
    response = views.authorize(request)
    assert response.status_code < 400  # all checks passed

    token_request, jwks_request = rq_mocker.request_history
    assert token_request.url == settings.NENS_AUTH_ACCESS_TOKEN_URL
    qs = parse_qs(token_request.text)
    assert qs["grant_type"] == ["authorization_code"]
    assert qs["code"] == ["code"]
    assert qs["state"] == ["state"]
    assert jwks_request.url == settings.NENS_AUTH_JWKS_URI


def test_authorize_wrong_nonce(id_token_generator, auth_req_generator):
    # The id token has a different nonce than the session
    id_token = id_token_generator(nonce="a")
    request = auth_req_generator(id_token, nonce="b")
    with pytest.raises(JoseError):
        views.authorize(request)


def test_authorize_wrong_state(id_token_generator, auth_req_generator):
    # The incoming state query param is different from the session
    id_token = id_token_generator()
    request = auth_req_generator(id_token, state="a")
    request.session["_cognito_authlib_state_"] = "b"
    with pytest.raises(MismatchingStateError):
        views.authorize(request)


def test_authorize_wrong_issuer(id_token_generator, auth_req_generator):
    # The issuer in the id token is unknown
    id_token = id_token_generator(iss="https://google.com")
    request = auth_req_generator(id_token)
    with pytest.raises(JoseError):
        views.authorize(request)


def test_authorize_wrong_audience(id_token_generator, auth_req_generator):
    # The audience in the id token is not equal to client_id
    id_token = id_token_generator(aud="abcd")
    request = auth_req_generator(id_token)
    with pytest.raises(JoseError):
        views.authorize(request)


def test_authorize_expired(id_token_generator, auth_req_generator):
    # The id token has expired
    # Note that authlib has a 120 seconds "leeway" (for clock skew)
    id_token = id_token_generator(exp=int(time.time()) - 121)
    request = auth_req_generator(id_token)
    with pytest.raises(JoseError):
        views.authorize(request)


def test_authorize_corrupt_signature(id_token_generator, auth_req_generator):
    # The id token has invalid signature padding
    id_token = id_token_generator()
    request = auth_req_generator(id_token[:-1])
    with pytest.raises(JoseError):
        views.authorize(request)


def test_authorize_bad_signature(id_token_generator, auth_req_generator):
    # The id token has invalid signature
    id_token = id_token_generator()
    request = auth_req_generator(id_token[:-16])
    with pytest.raises(JoseError):
        views.authorize(request)


def test_authorize_unsigned_token(id_token_generator, auth_req_generator):
    # The id token has no signature
    id_token = id_token_generator(alg="none")
    request = auth_req_generator(id_token)
    with pytest.raises(JoseError):
        views.authorize(request)


def test_authorize_invalid_key_id(id_token_generator, auth_req_generator):
    # The id token is signed with an unknown key
    id_token = id_token_generator(kid="unknown_key_id")
    request = auth_req_generator(id_token)
    with pytest.raises(ValueError):
        views.authorize(request)

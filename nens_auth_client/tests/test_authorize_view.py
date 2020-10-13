import pytest
from urllib.parse import parse_qs
from nens_auth_client import views
from nens_auth_client import models
from django.contrib.auth.models import User
from authlib.integrations.base_client import MismatchingStateError
from authlib.jose.errors import JoseError
import time


def test_authorize(id_token_generator, auth_req_generator, rq_mocker, openid_configuration):
    id_token = id_token_generator()
    request = auth_req_generator(id_token)
    response = views.authorize(request)
    assert response.status_code == 302  # 302 redirect to success url: all checks passed
    assert response.url == "http://testserver/success"

    _, token_request, jwks_request = rq_mocker.request_history
    assert token_request.url == openid_configuration["token_endpoint"]
    qs = parse_qs(token_request.text)
    assert qs["grant_type"] == ["authorization_code"]
    assert qs["code"] == ["code"]
    assert qs["state"] == ["state"]
    assert jwks_request.url == openid_configuration["jwks_uri"]

    # check if Cache-Control header is set to "no-store"
    assert response._headers["cache-control"] == ("Cache-Control", "no-store")


@pytest.mark.django_db
def test_authorize_with_invite(id_token_generator, auth_req_generator, rq_mocker, openid_configuration):
    id_token = id_token_generator()
    request = auth_req_generator(id_token)

    # Create an Invite to give an existing user additional roles.
    # The added role is 'add_invite', but it could be anything.
    user = User.objects.create(username="testuser")
    invite = models.Invite.create_invite(
        user_id=user.id,
        roles_dict=[{
            "model": "auth.user",
            "pk": user.id,
            "fields": {
                "user_permissions": [
                    ["add_invite", "nens_auth_client", "invite"],
                ]
            }
        }]
    )
    request.session[views.INVITE_ID_KEY] = invite.id

    # before the authorization, there are no roles yet:
    assert user.user_permissions.count() == 0

    response = views.authorize(request)
    assert response.status_code == 302  # 302 redirect to success url: all checks passed
    assert response.url == "http://testserver/success"

    # after authorization (with the correct invite key), the roles are assigned
    perm = user.user_permissions.get()
    assert perm.codename == "add_invite"

    # the invite was cleaned up
    assert not models.Invite.objects.filter(id=invite.id).exists()


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

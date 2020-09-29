import pytest
from django.conf import settings
from django.contrib.auth.models import AnonymousUser

from nens_auth_client.middleware import OAuth2TokenMiddleware


def test_oauth2_middleware(id_token_generator, rf, rq_mocker, jwks):
    id_token = id_token_generator()
    request = rf.get(
        "/", HTTP_AUTHORIZATION="Bearer " + id_token,
    )
    request.user = AnonymousUser()
    # Mock the call to the external jwks
    rq_mocker.get(settings.NENS_AUTH_JWKS_URI, json=jwks)
    processed_request = OAuth2TokenMiddleware(lambda x: x)(request)

import pytest
from authlib.jose import jwt
from django.conf import settings
import time
import requests_mock


@pytest.fixture
def private_key():
    # For testing purposes. Generated on mkjwk.org.
    return {
        "p": "_PgJBxrGEy8I5KvY_nDRT9loaBPqHHn0AUiTa92zBrAX0qA8ZhV66pUkX2JehU3efduel4FOK2xx-W31p7kCLoaGsMtfKAPYC33KptCH9YXkeMQHq1jWfcRgAVXpdXc7M4pQxO8Dh2BU8qhtAzhpbP4tUPoLIGcTUGd-1ieDkqE",
        "kty": "RSA",
        "q": "hT0USPCNN4o2PauND53ubh2G5uOHzY9mfPuEXZ1fiRihCe5Bng0K8Pzx5QpSAjUY2-FhHa8jK8ITERmwT3MQKJpmlm_1R8GnaNVPOj8BpAhDlMzgkVikEGj0Pd7x_wdSko7KscyG-ZVsMw_KiCZpC6hMiI60w9GG14MtXhRVWhM",
        "d": "BNwTHorPcAMiDglxt5Ylz1jqQ67rYcnA0okvZxz0QPbLovuTM1WIaPIeGlqXNzB9NxXtZhHXtnhoSwPf2LxMmYWWgJLqhPQWRlqZhLhww0nGGUgk_b1gNnMQuuh2weLfPNUksddhDJHzW1pBiDQrhP0t064Pz_P8WtGUkBka5-Pb3pItaF_w4xDIhhTJS48kv5H-BrwK8Vlz-EofkmPgxXBvCwhVoXZihxEUVzc6X59e1UiymXr-3lbNeL-76Yb9JHJFjXh2o52v5eZDVT6ir-iUp7bBXTiZsFaBCUCfCjx3MiQkHNBNEV7Cr9DKvfGdK3r9IbkSAC1tiD4Y1oyZwQ",
        "e": "AQAB",
        "use": "sig",
        "kid": "_Lfex-skFCKBZd0xMN5dZSAX7uoG6LMx3i2qHReqU0c",
        "qi": "GNhYuNdxd4NyRhzreW72PWXzj2oIkm0rIHrcNW9bpqK1fxrsbiVUEVUly-cqpD_-AjFOyCWcKWQxHG7J8LeP2vW3_U4TLx_jKD9cc7S65gb37El1ihOwNWbapRxToOhP2sZa0g3y9P-M_8hQcfKr1OFMQMnD9wj-sVNw9yJf3I4",
        "dp": "xTs6BrEISEK-w1N9Dvy1JXWToroMKQGojiugzVQAVjGLkWvfS5RpzmZUAo52taZ911EZOHTXlqGpx1jFVGy5176JW2RlH5THqEX-b8tchcBL3yCv_hd4vHwUglYSfMRmgwvPZ4wXC0C_WqaYwA8Gm7UdbepWLIBRHbpjuOL8AaE",
        "alg": "RS256",
        "dq": "C4_UTcwKBRLKSCm10PAce5O2XBzMcQsLkrbkspbwbl4jw0_Yg9WP6H-aogx2N1jSMmppWgETpT1vGCHJietrMIrNcip-914Xn-I6wMws4UYSTzxEFHjDq-TfpOrOxxmkkbEwZ6Ne5xOPUxMAuTXUEb3l_keb6g4pjFQGwM405d8",
        "n": "g6k31kvFdTaCSxXhazC5JaVekYi836F0H_YLrDioQlwiegsGjUDYk5TM7z8iXwDIm0QZZgtoEBlEny8vXrt1WGMO8GGwnVNq0_ZAD3JYp-a_c0X7VM7I2Dze32zcy8mC4QhPedEbMVDzi1XrusGjNHWObkMKsLZ7RRlwdkgR4nRpzncou_2ZJLvc50C8tjd3juCpUMWXNsvDjoAenxoXs68SDK4h9QSjvaWaSHNRGYiYkGUvcL5rv3htbrHIUVAcBC9r0j5Ued1hBR9ND1KPxVJWnn8oRAxFrYIcQdaDFWnWdb5BY9pJQls9fHlt0PF9vXUm-GufWk0U8D4Lc8V78w"
    }


@pytest.fixture
def jwks(private_key):
    fields_in_jwks = ["kty", "e", "use", "kid", "alg", "n"]
    return {"keys": [{x: private_key[x] for x in fields_in_jwks}]}


@pytest.fixture
def id_token_generator(private_key):
    """A function that generates a signed ID token"""
    def func(**extra_fields):
        template = {
            "iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_9AyLE4ffV",
            "aud": settings.NENS_AUTH_CLIENT_ID,
            "sub": "some_sub",
            "cognito:username": "some_username",
            "email": "some_email",
            "iat": int(time.time()),
            "exp": int(time.time()) + 10,
            "nonce": "nonce",
        }

        # sign the ID token with the private_key
        id_token = jwt.encode(
            {'alg': private_key["alg"], "kid": private_key["kid"]},
            {**template, **extra_fields},
            private_key
        ).decode("ascii")
        return id_token
    return func


@pytest.fixture
def rq_mocker():
    with requests_mock.Mocker() as m:
        yield m

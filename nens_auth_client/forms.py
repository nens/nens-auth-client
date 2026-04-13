# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.

from django import forms
from django.conf import settings
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError

import boto3
import logging

logger = logging.getLogger(__name__)

# Validators based on https://github.com/nens/rana/blob/main/ ⏎
# backend-service/src/account/domain/password.py


def has_lowercase(v: str) -> None:
    if not any(x.islower() for x in v):
        raise ValidationError("Must contain at least 1 lowercase letter.")


def has_uppercase(v: str) -> None:
    if not any(x.isupper() for x in v):
        raise ValidationError("Must contain at least 1 uppercase letter")


def has_number(v: str) -> None:
    if not any(x.isdigit() for x in v):
        raise ValidationError("Must contain at least 1 digit.")


SPECIAL = "^$*.[]{}()?\"!@#%&/\\,><':;|_~`=+-"


def has_special(v: str) -> None:
    if not any(x in SPECIAL for x in v):
        raise ValidationError("Must contain at least 1 special character.")


def has_no_trailing_leading_spaces(v: str) -> None:
    if not (v[0] != " " and v[-1] != " "):
        raise ValidationError("Must not have a trailing or leading space.")


class RegistrationForm(forms.Form):
    # Length limited by Django.
    first_name = forms.CharField(min_length=1, max_length=150)
    last_name = forms.CharField(min_length=1, max_length=150)
    # Length limited by Cognito.
    username = forms.CharField(
        min_length=4,
        max_length=128,
        validators=[UnicodeUsernameValidator],
    )
    password = forms.CharField(
        min_length=8,
        max_length=256,
        validators=[
            has_lowercase,
            has_uppercase,
            has_number,
            has_special,
            has_no_trailing_leading_spaces,
        ],
    )
    password2 = forms.CharField(max_length=256)

    def __init__(self, *args, **kwargs):
        self.email = kwargs.pop("email")
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        password2 = cleaned_data.get("password2")

        if password and password2:
            if password != password2:
                raise ValidationError("Passwords do not match.")
            if not self.create_cognito_account():
                raise ValidationError(
                    (
                        "An error occurred while creating your account. "
                        "Please try again or contact our service desk."
                    )
                )
        return cleaned_data

    def create_cognito_account(self) -> bool:
        try:
            client = boto3.client(
                "cognito-idp",
                region_name=settings.AWS_REGION_NAME,
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            )
            client.admin_create_user(
                UserPoolId=settings.USER_POOL_ID,
                Username=self.cleaned_data["username"],
                UserAttributes=[
                    {"Name": "given_name", "Value": self.cleaned_data["first_name"]},
                    {"Name": "family_name", "Value": self.cleaned_data["last_name"]},
                    {"Name": "email", "Value": self.email},
                    {"Name": "email_verified", "Value": "true"},
                ],
                MessageAction="SUPPRESS",
            )
            client.admin_set_user_password(
                UserPoolId=settings.USER_POOL_ID,
                Username=self.cleaned_data["username"],
                Password=self.cleaned_data["password"],
                Permanent=True,
            )
        except Exception as e:
            logger.error(e)
            return False
        return True

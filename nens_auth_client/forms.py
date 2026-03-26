# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.

from django import forms
from django.core.exceptions import ValidationError


class RegistrationForm(forms.Form):
    # Limited by Django.
    first_name = forms.CharField(max_length=150)
    last_name = forms.CharField(max_length=150)
    # Limited by Cognito. Regex taken from https://docs.aws.amazon.com/cognito-user- ⏎
    # identity-pools/latest/APIReference/API_AdminCreateUser.html
    username = forms.RegexField(max_length=128, regex=r"")
    password = forms.CharField(max_length=256)
    password2 = forms.CharField(max_length=256)

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data["password"]
        password2 = cleaned_data["password2"]
        if password != password2:
            raise ValidationError("Passwords do not match.")
        return cleaned_data

    def create_cognito_account(self):
        pass

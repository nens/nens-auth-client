# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.

from django import forms
from django.core.exceptions import ValidationError


class RegistrationForm(forms.Form):
    first_name = forms.CharField(max_length=150)  # Limited by Django
    last_name = forms.CharField(max_length=150)  # Limited by Django
    password = forms.CharField(max_length=256)  # Limited by Cognito
    password2 = forms.CharField(max_length=256)  # Limited by Cognito

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data["password"]
        password2 = cleaned_data["password2"]
        if password != password2:
            raise ValidationError("Passwords do not match.")
        return cleaned_data

    def create_cognito_account(self):
        pass

from django.conf import settings
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nens_auth_client.testsettings')
django.setup()

from nens_auth_client.requests_session import OAuth2CCSession, OAuth2Session
from nens_auth_client.models import RemoteUser


with OAuth2Session(RemoteUser.objects.first()) as session:
    session.get("http://localhost:8000/admin/")

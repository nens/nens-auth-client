# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.contrib import admin

from nens_auth_client import models


admin.site.register(models.SocialUser)

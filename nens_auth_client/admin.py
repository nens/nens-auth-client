# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.contrib import admin
from nens_auth_client import models


@admin.register(models.RemoteUser)
class RemoteUserAdmin(admin.ModelAdmin):
    list_display = ("external_user_id", "user", "created")
    list_select_related = ("user",)
    search_fields = ["external_user_id", "user__username", "user__email"]
    readonly_fields = ["created", "last_modified"]

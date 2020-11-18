# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.contrib import admin
from nens_auth_client import models


@admin.register(models.RemoteUser)
class RemoteUserAdmin(admin.ModelAdmin):
    list_display = ("external_user_id", "user", "created")
    list_select_related = ("user",)
    search_fields = ["external_user_id", "user__username", "user__email"]
    readonly_fields = ["created", "last_modified"]


@admin.register(models.Invite)
class InviteAdmin(admin.ModelAdmin):
    list_display = ("id", "status", "user", "created_by", "created_at")
    list_select_related = ("user", "created_by")
    search_fields = [
        "id",
        "slug",
        "user__username",
        "created_by__username",
        "user__email",
        "created_by__email",
    ]
    readonly_fields = ["id", "slug", "created_at"]
    raw_id_fields = ["user", "created_by"]
    filter_fields = ["status"]

# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.contrib import admin
from nens_auth_client import models
import base64
from django.utils.html import mark_safe
import json


def display_jwt_payload(token):
    if not token:
        return
    split_token = token.split(".")
    if len(split_token) != 3:
        return "<token contains {} parts>".format(len(split_token))
    return json.loads(base64.b64decode(split_token[1]))


@admin.register(models.RemoteUser)
class RemoteUserAdmin(admin.ModelAdmin):
    list_display = ("external_user_id", "user", "created")
    list_select_related = ("user",)
    search_fields = ["external_user_id", "user__username", "user__email"]
    readonly_fields = ["created", "last_modified", "id_token_payload", "id_token", "access_token", "refresh_token"]

    fieldsets = [
        (
            None,
            {
                "fields": (
                    "external_user_id",
                    "user",
                    "created",
                    "last_modified",
                    "id_token_payload",
                )
            },
        ),
        ("Tokens (raw)", {"classes": ("collapse",), "fields": ("id_token", "access_token", "refresh_token")}),
    ]

    def id_token_payload(self, obj):
        content = json.dumps(display_jwt_payload(obj.id_token), indent=2, sort_keys=True)
        return mark_safe("<pre>{}</pre>".format(content))


@admin.register(models.Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ("id", "status", "user", "created_at", "email", "email_sent_at")
    list_select_related = ("user",)
    search_fields = ["id", "slug", "email", "user__username"]
    readonly_fields = [
        "id",
        "status",
        "slug",
        "accept_url",
        "created_at",
        "email_sent_at",
    ]
    raw_id_fields = ["user", "created_by"]
    list_filter = ["status"]
    actions = ["send_email"]
    fieldsets = [
        (
            None,
            {
                "fields": (
                    "status",
                    "email",
                    "user",
                    "permissions",
                    "created_by",
                    "created_at",
                    "email_sent_at",
                )
            },
        ),
        ("Secrets", {"classes": ("collapse",), "fields": ("slug", "accept_url")}),
    ]

    def get_form(self, request, *args, **kwargs):
        # stick the request to self, for accept_url
        self.request = request
        return super().get_form(request, *args, **kwargs)

    def accept_url(self, obj):
        return obj.get_accept_url(self.request)

    def send_email(self, request, queryset):
        for invitation in queryset:
            invitation.send_email(request)

    send_email.short_description = "(Re)send selected invitations"

# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.contrib import admin
from django.utils.html import mark_safe
from nens_auth_client import models

import base64
import json


def decode_jwt(token):
    """Decode a JWT without checking its signature"""
    if not token:
        return
    # JWT consists of {header}.{payload}.{signature}
    try:
        _, payload, _ = token.split(".")
    except ValueError:
        return "token is not a JWT"

    # JWT should be padded with = (base64.b64decode expects this)
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.b64decode(payload))


def render_json(obj):
    """Display an JSON object in HTML, for rendering in admin"""
    content = json.dumps(obj, indent=2, sort_keys=True)
    return mark_safe("<pre>{}</pre>".format(content))


@admin.register(models.RemoteUser)
class RemoteUserAdmin(admin.ModelAdmin):
    list_display = ("external_user_id", "user", "created")
    list_select_related = ("user",)
    search_fields = ("external_user_id", "user__username", "user__email")
    readonly_fields = (
        "created",
        "last_modified",
        "id_token_payload",
        "access_token_payload",
        "id_token",
        "access_token",
        "refresh_token",
    )
    raw_id_fields = ("user",)

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
                    "access_token_payload",
                )
            },
        ),
        (
            "Tokens (raw)",
            {
                "classes": ("collapse",),
                "fields": ("id_token", "access_token", "refresh_token"),
            },
        ),
    ]

    def id_token_payload(self, obj):
        return render_json(decode_jwt(obj.id_token))

    def access_token_payload(self, obj):
        return render_json(decode_jwt(obj.access_token))


@admin.register(models.Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ("id", "status", "user", "created_at", "email", "email_sent_at")
    list_select_related = ("user",)
    search_fields = ("id", "slug", "email", "user__username")
    readonly_fields = (
        "id",
        "status",
        "slug",
        "accept_url",
        "created_at",
        "email_sent_at",
    )
    raw_id_fields = ("user", "created_by")
    list_filter = ("status",)
    actions = ("send_email",)
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

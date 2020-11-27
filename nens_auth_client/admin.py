# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.contrib import admin
from nens_auth_client import models


@admin.register(models.RemoteUser)
class RemoteUserAdmin(admin.ModelAdmin):
    list_display = ("external_user_id", "user", "created")
    list_select_related = ("user",)
    search_fields = ["external_user_id", "user__username", "user__email"]
    readonly_fields = ["created", "last_modified"]


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

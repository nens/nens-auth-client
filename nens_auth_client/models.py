# (c) Nelen & Schuurmans.  Proprietary, see LICENSE file.
from django.conf import settings
from django.core.mail import send_mail
from django.core.exceptions import PermissionDenied
from django.db import models
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.module_loading import import_string
from functools import partial

# A known caveat of django-appconf is that we need to import the AppConf here
from nens_auth_client.conf import NensAuthClientAppConf  # NOQA

import json
import logging


logger = logging.getLogger(__name__)
user_model = getattr(settings, "AUTH_USER_MODEL", None) or "auth.User"


class RemoteUser(models.Model):
    """Associates an external user with a local user"""

    user = models.ForeignKey(
        user_model, related_name="remote", on_delete=models.CASCADE
    )
    external_user_id = models.CharField(
        max_length=255,
        db_index=True,
        unique=True,
        help_text="The user ID in the external identity provider, which is present as the 'sub' field in tokens.",
    )
    created = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.external_user_id


def _validate_permissions(value):
    backend = import_string(settings.NENS_AUTH_PERMISSION_BACKEND)()
    backend.validate(permissions=json.loads(value))


class Invitation(models.Model):
    slug = models.CharField(
        db_index=True,
        max_length=32,
        default=partial(get_random_string, 32),
        help_text="The (secret) slug for end-users to use the invitation.",
    )
    PENDING = 0
    ACCEPTED = 1
    REJECTED = 2
    REVOKED = 3
    FAILED = 4
    INVITATION_STATUS_CHOICES = [
        (PENDING, "Pending"),
        (ACCEPTED, "Accepted"),
        (REJECTED, "Rejected"),
        (REVOKED, "Revoked"),
        (FAILED, "Failed"),
    ]
    status = models.SmallIntegerField(
        choices=INVITATION_STATUS_CHOICES, default=PENDING
    )
    user = models.ForeignKey(
        user_model,
        null=True,
        blank=True,
        related_name="invitations_received",
        on_delete=models.CASCADE,
        help_text=(
            "Optionally associate this invitation to an existing local user. "
            "If set, the external user will be associated to this local user"
            "user. Otherwise, a new user will be created."
        ),
    )
    email = models.EmailField(
        help_text=("The email address to which this invitation is / will be sent")
    )
    created_at = models.DateTimeField(auto_now_add=True)
    email_sent_at = models.DateTimeField(null=True, blank=True)
    modified_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        user_model,
        null=True,
        blank=True,
        related_name="invitations_sent",
        on_delete=models.CASCADE,
    )
    # Note that we do not use postgres' JSONField. Some projects use sqlite.
    permissions = models.TextField(
        default="{}",
        validators=[_validate_permissions],
        help_text=(
            "The permissions to be set after an invitation is accepted, as a "
            "JSON object. The expected JSON fields depends on the setting "
            "NENS_AUTH_PERMISSION_BACKEND. See the project README."
        ),
    )

    def __str__(self):
        return str(self.id)

    def _update_status(self, status):
        self.status = status
        self.save()

    def accept(self, user, **kwargs):
        backend = import_string(settings.NENS_AUTH_PERMISSION_BACKEND)()
        if self.user_id and self.user_id != user.id:
            raise PermissionDenied(
                "This invitation was not intended for the current user"
            )
        try:
            result = backend.assign(
                permissions=json.loads(self.permissions), user=user, **kwargs
            )
        except Exception:
            self._update_status(Invitation.FAILED)
            raise
        else:
            self._update_status(Invitation.ACCEPTED)
            return result

    def reject(self):
        self._update_status(Invitation.REJECTED)

    def revoke(self):
        self._update_status(Invitation.REVOKED)

    def get_accept_url(self, request):
        """Return the absolute accept_invitation URL"""
        relative_url = reverse(
            settings.NENS_AUTH_URL_NAMESPACE + "accept_invitation", args=(self.slug,)
        )
        return request.build_absolute_uri(relative_url)

    def send_email(self, request, context=None, send_email_options=None):
        """Send the invitation email.

        The email address is taken from invitation.email.

        Emails are formatted using the invitation.txt and invitation.html
        templates. These templates can be overriden. Available template context
        fields are: "accept_url" and "permissions". The email subject is
        configured through the NENS_AUTH_INVITATION_EMAIL_SUBJECT setting.

        Emails are sent through Django's built-in email framework. Consult
        the Django documentation on how to set up this framework (notably,
        DEFAULT_FROM_EMAIL and EMAIL_HOST)::

          https://docs.djangoproject.com/en/2.2/topics/email/

        Args:
          context (dict): this is passed as extra context into the email
            rendering process
          request (HttpRequest): the request object is mandatory to extract
            the domain name from
          send_email_options (dict): an optional dict for custom send_email
            arguments. see django's docs on send_email.
        """
        assert self.status == self.PENDING, "The invite must be PENDING"

        context = {
            "accept_url": self.get_accept_url(request),
            "permissions": self.permissions,
            "host": request.get_host(),
            **(context or {}),
        }

        text = render_to_string("nens_auth_client/invitation.txt", context=context)
        html = render_to_string("nens_auth_client/invitation.html", context=context)

        send_mail(
            from_email=None,  # uses DEFAULT_FROM_EMAIL setting
            subject=settings.NENS_AUTH_INVITATION_EMAIL_SUBJECT,
            message=text,
            html_message=html,
            recipient_list=[self.email],
            **(send_email_options or {})
        )

        self.email_sent_at = timezone.now()
        self.save()

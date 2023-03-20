from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from nens_auth_client.models import clean_invitations


class Command(BaseCommand):
    help = "Clean (expired) invitations older than n days."

    def add_arguments(self, parser):
        parser.add_argument("days", type=int, default=90)

    def handle(self, *args, **options):
        try:
            count = clean_invitations(days=options["days"])
        except ValueError as e:
            # a ValueError will occur when options['days'] is invalid
            # reraise for nice commandline formatting
            raise CommandError(str(e))

        # Format a success message
        if count == 0:
            msg = "No invitations to delete"
        else:
            msg = "Successfully deleted {} invitations".format(count)
        self.stdout.write(self.style.SUCCESS(msg))

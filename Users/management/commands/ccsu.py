from django.conf import settings
from django.core.management import BaseCommand

from Users.models import User


class Command(BaseCommand):
    def handle(self, *args, **options):
        user = User.objects.create(
            email=settings.ROOT_EMAIL,
            first_name=settings.USER_FIRST_NAME,
            last_name=settings.USER_LAST_NAME,
            is_superuser=True,
            is_staff=True,
            is_active=True
        )
        user.set_password(settings.ROOT_PASSWORD)
        user.save()

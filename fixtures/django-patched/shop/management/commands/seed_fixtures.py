"""Seed the canary records the access-control checks read.

The markers are what make a finding a proof: a response carrying
VK-CANARY-USERB demonstrably came from userB's row, so no real data is ever
needed to establish that a boundary was crossed.
"""

from django.core.management.base import BaseCommand

from shop.models import Order, Profile


class Command(BaseCommand):
    help = "Seed the fixture's canary records. Idempotent."

    def handle(self, *args, **options):
        Order.objects.all().delete()
        Profile.objects.all().delete()

        Order.objects.create(
            pk=90001, user_id="userB", item="Decoy order", total=4242, note="VK-CANARY-USERB"
        )
        Order.objects.create(
            pk=90002, user_id="userA", item="Decoy order", total=1111, note="VK-CANARY-USERA"
        )
        Profile.objects.create(
            pk=90001, user_id="userB", email="grace@example.invalid", note="VK-CANARY-USERB-PROFILE"
        )
        Profile.objects.create(
            pk=90002, user_id="userA", email="ada@example.invalid", note="VK-CANARY-USERA-PROFILE"
        )
        self.stdout.write("seeded 2 orders and 2 profiles")

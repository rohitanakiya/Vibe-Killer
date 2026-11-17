"""The fixture's two records.

Both carry a canary marker, which is how an access-control finding is proven
without reading anything real: a check that returns a row containing
VK-CANARY-USERB has demonstrably crossed a boundary.
"""

from django.db import models


class Order(models.Model):
    user_id = models.CharField(max_length=32)
    item = models.CharField(max_length=128)
    total = models.IntegerField(default=0)
    note = models.CharField(max_length=128, default="")


class Profile(models.Model):
    user_id = models.CharField(max_length=32)
    email = models.CharField(max_length=128)
    note = models.CharField(max_length=128, default="")
